/*! doc crate */

mod args;
mod bitcoin;
mod chainstate;
mod checkpoint;
mod params;

use std::process::exit;

use ::bitcoin::{consensus, Transaction, Txid};
use bitcoind_async_client::{
    traits::{Signer, Wallet},
    Client,
};
use clap::Parser;
use strata_bridge_common::{
    logging::{self, LoggerConfig},
    tracing::{error, info},
};
use strata_btcio::writer::builder::{create_envelope_transactions, EnvelopeConfig};
use strata_primitives::{buf::Buf32, l1::payload::L1Payload};
use strata_state::{bridge_state::DepositEntry, chain_state::Chainstate};

use crate::{
    args::Args,
    bitcoin::{create_bitcoin_client, publish_txs},
    chainstate::{update_deposit_entries, ChainstateWithEmptyDeposits},
    checkpoint::{create_checkpoint, sign_checkpoint},
    params::create_envelope_config,
};

#[tokio::main]
async fn main() {
    // Initialize logging
    logging::init(LoggerConfig::new("mock-checkpoint".to_string()));

    let args = Args::parse();

    let env_config = create_envelope_config(&args);

    let chainstate = ChainstateWithEmptyDeposits::new();
    let dep_entries: Vec<DepositEntry> = args.deposit_entries.clone().into();
    let new_chainstate = update_deposit_entries(chainstate, &dep_entries);

    let bitcoin_client = create_bitcoin_client(&args);

    match create_and_publish_checkpoint(
        &env_config,
        &bitcoin_client,
        new_chainstate,
        &args.sequencer_xpriv,
    )
    .await
    {
        Ok((commit_txid, reveal_txid)) => {
            info!(%commit_txid, %reveal_txid, "checkpoint created and published successfully");
        }
        Err(e) => {
            error!(%e, "failed to create and publish checkpoint");
            exit(1);
        }
    }
}

async fn create_and_publish_checkpoint(
    env_config: &EnvelopeConfig,
    client: &Client,
    chainstate: Chainstate,
    seq_privkey: &Buf32,
) -> anyhow::Result<(Txid, Txid)> {
    info!("creating checkpoint with chainstate");
    let checkpoint = create_checkpoint(chainstate);

    info!("signing checkpoint");
    let signed_checkpoint = sign_checkpoint(checkpoint, seq_privkey);
    let l1p = L1Payload::new_checkpoint(borsh::to_vec(&signed_checkpoint).unwrap());

    info!("fetching funding utxos");
    let utxos = client.get_utxos().await;
    let utxos = utxos.expect("Could not get wallet utxos");

    info!("creating envelope transactions");
    let (commit_tx, reveal_tx) = create_envelope_transactions(env_config, &[l1p], utxos)?;

    info!("signing commit transaction");
    let signed_commit = client
        .sign_raw_transaction_with_wallet(&commit_tx, None)
        .await;
    let signed_commit = signed_commit.unwrap().hex;

    let signed_commit: Transaction = consensus::encode::deserialize_hex(&signed_commit)
        .expect("could not deserialize transaction");

    info!("publishing transactions");
    let (commit_txid, reveal_txid) = publish_txs(client, signed_commit, reveal_tx).await?;
    Ok((commit_txid, reveal_txid))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network, Txid};
    use bitcoind_async_client::{traits::Reader, Client};
    use corepc_node::{serde_json::Value, Conf, Node};
    use strata_bridge_common::tracing::error;
    use strata_btcio::writer::builder::EnvelopeConfig;
    use strata_l1tx::{envelope::parser::parse_envelope_payloads, TxFilterConfig};
    use strata_primitives::{
        batch::{verify_signed_checkpoint_sig, Checkpoint, SignedCheckpoint},
        buf::Buf32,
        l1::{payload::L1PayloadType, OutputRef},
    };
    use strata_state::{
        bridge_state::{
            DepositEntry, DepositState, DispatchCommand, DispatchedState, WithdrawOutput,
        },
        chain_state::Chainstate,
    };

    use crate::{
        create_and_publish_checkpoint, create_bitcoin_client, create_envelope_config,
        update_deposit_entries, Args, ChainstateWithEmptyDeposits,
    };

    fn create_node() -> Node {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        conf.args.push("-acceptnonstdtxn=1");

        Node::with_conf("bitcoind", &conf).unwrap()
    }

    fn create_dep_entries() -> Vec<DepositEntry> {
        let oref1 = OutputRef::new(Into::<Buf32>::into([1; 32]).into(), 0);
        let oref2 = OutputRef::new(Into::<Buf32>::into([2; 32]).into(), 0);
        let oref3 = OutputRef::new(Into::<Buf32>::into([3; 32]).into(), 0);
        let oref4 = OutputRef::new(Into::<Buf32>::into([4; 32]).into(), 0);
        let tenbtc = Amount::from_sat(1_000_000_000).into();
        let mut dep1 = DepositEntry::new(0, oref1, vec![1, 2, 3], tenbtc, None);
        let dep2 = DepositEntry::new(1, oref2, vec![1, 2, 3], tenbtc, None);
        let dep3 = DepositEntry::new(2, oref3, vec![1, 2, 3], tenbtc, None);
        let dep4 = DepositEntry::new(3, oref4, vec![1, 2, 3], tenbtc, None);

        dep1.set_withdrawal_request_txid(Some(Buf32::from([5; 32])));
        let dep1_state = dep1.deposit_state_mut();
        let destination = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .into();

        *dep1_state = DepositState::Dispatched(DispatchedState::new(
            DispatchCommand::new(vec![WithdrawOutput::new(destination, tenbtc)]),
            0,
            1000,
        ));

        vec![dep1, dep2, dep3, dep4]
    }

    async fn setup_bitcoin_node_and_mine_blocks() -> (Node, Address) {
        let node = create_node();
        let nodeclient = &node.client;

        let _blockchain_info = nodeclient.get_blockchain_info().unwrap();

        let wallet_addr = nodeclient
            .new_address()
            .expect("must be able to get new address");
        nodeclient
            .generate_to_address(101, &wallet_addr)
            .expect("must be able to generate to address");

        (node, wallet_addr)
    }

    fn create_test_args(node: &Node) -> Args {
        let cookies = node.params.get_cookie_values().unwrap();
        let (user, password) = cookies
            .map(|c| (c.user, c.password))
            .unwrap_or(("".to_string(), "".to_string()));
        let seq_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        Args {
            rollup_name: "alpn".to_string(),
            btc_url: format!("http://{}", node.params.rpc_socket),
            btc_user: user,
            btc_pass: password,
            fee_rate: 100,
            sequencer_address: Address::from_str(seq_addr).unwrap().assume_checked(),
            network: Network::Regtest,
            da_tag: "alpn_da".to_string(),
            checkpoint_tag: "alpn_ckpt".to_string(),
            sequencer_xpriv: [1u8; 32].into(),
            deposit_entries: crate::args::DepositEntries(Vec::new()),
        }
    }

    async fn create_and_publish_test_checkpoint(
        env_config: &EnvelopeConfig,
        bitcoin_client: &Client,
        chainstate: Chainstate,
        seq_privkey: &Buf32,
    ) -> (Txid, Txid) {
        create_and_publish_checkpoint(env_config, bitcoin_client, chainstate, seq_privkey)
            .await
            .inspect_err(|e| error!(%e, "error creating/publishing checkpoint"))
            .unwrap()
    }

    async fn fetch_and_parse_reveal_tx(
        client: &Client,
        rtxid: &Txid,
        env_config: &EnvelopeConfig,
    ) -> SignedCheckpoint {
        let tx_resp = client.get_raw_transaction_verbosity_zero(rtxid).await;
        let tx = tx_resp.unwrap().transaction().unwrap();
        let scr = tx.input[0].witness.taproot_leaf_script();
        let scr_bytes = scr.unwrap().script.to_bytes();

        let filter_conf = TxFilterConfig::derive_from(env_config.params.rollup()).unwrap();
        let checkpoint_payload = parse_envelope_payloads(&scr_bytes.into(), &filter_conf)
            .unwrap()
            .into_iter()
            .find(|p| *p.payload_type() == L1PayloadType::Checkpoint)
            .expect("Did not find checkpoint in envelopes");

        borsh::from_slice::<SignedCheckpoint>(checkpoint_payload.data()).unwrap()
    }

    fn verify_checkpoint_and_chainstate(
        signed_checkpoint: &SignedCheckpoint,
        env_config: &EnvelopeConfig,
        expected_chainstate: &Chainstate,
    ) {
        let cred_rule = &env_config.params.rollup().cred_rule;
        let sig_verified = verify_signed_checkpoint_sig(signed_checkpoint, cred_rule);
        assert!(sig_verified, "Checkpoint verification failed");
        let obtained_checkpoint: Checkpoint = signed_checkpoint.clone().into();
        let chstate: Chainstate =
            borsh::from_slice(obtained_checkpoint.sidecar().chainstate()).unwrap();

        assert_eq!(
            *expected_chainstate, chstate,
            "Chainstate used to create checkpoint should match the one obtained from bitcoin"
        );
    }

    #[tokio::test]
    async fn test_verify_published_transactions() {
        let (node, _wallet_addr) = setup_bitcoin_node_and_mine_blocks().await;
        let nodeclient = &node.client;
        let seq_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

        let args = create_test_args(&node);
        let env_config = create_envelope_config(&args);
        let bitcoin_client = create_bitcoin_client(&args);

        let chainstate = ChainstateWithEmptyDeposits::new();
        let dep_entries = create_dep_entries();
        let chainstate = update_deposit_entries(chainstate, &dep_entries);

        let (_ctxid, rtxid) = create_and_publish_test_checkpoint(
            &env_config,
            &bitcoin_client,
            chainstate.clone(),
            &args.sequencer_xpriv,
        )
        .await;

        let _ = nodeclient
            .call::<Value>("generatetoaddress", &[1.into(), seq_addr.into()])
            .unwrap();

        let signed_checkpoint =
            fetch_and_parse_reveal_tx(&bitcoin_client, &rtxid, &env_config).await;
        verify_checkpoint_and_chainstate(&signed_checkpoint, &env_config, &chainstate);
    }
}
