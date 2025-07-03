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
use strata_btcio::writer::builder::{create_envelope_transactions, EnvelopeParams};
use strata_primitives::{buf::Buf32, l1::payload::L1Payload};
use strata_state::chain_state::Chainstate;

use crate::{
    args::Args,
    bitcoin::{create_bitcoin_client, publish_txs},
    chainstate::{update_deposit_entries, ChainstateWithEmptyDeposits},
    checkpoint::{create_checkpoint, sign_checkpoint},
    params::create_envelope_params,
};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let env_params = create_envelope_params(&args);

    let chainstate = ChainstateWithEmptyDeposits::new();
    let new_chainstate = update_deposit_entries(chainstate, &args.deposit_entries);

    let bitcoin_client = create_bitcoin_client(&args);
    if let Err(e) = create_and_publish_checkpoint(
        &env_params,
        &bitcoin_client,
        new_chainstate,
        &args.sequencer_private_key,
    )
    .await
    {
        eprintln!("Failed to publish txs: {e}");
        exit(1);
    }
}

async fn create_and_publish_checkpoint(
    env_params: &EnvelopeParams,
    bitcoin_client: &Client,
    chainstate: Chainstate,
    seq_privkey: &Buf32,
) -> anyhow::Result<(Txid, Txid)> {
    let checkpoint = create_checkpoint(chainstate);
    let signed_checkpoint = sign_checkpoint(checkpoint, seq_privkey);
    let l1p = L1Payload::new_checkpoint(borsh::to_vec(&signed_checkpoint).unwrap());

    let utxos = bitcoin_client
        .get_utxos()
        .await
        .expect("Could not get wallet utxos");

    let (commit_tx, reveal_tx) = create_envelope_transactions(env_params, &[l1p], utxos)?;
    let commit_txid = commit_tx.compute_txid();
    let reveal_txid = reveal_tx.compute_txid();

    // Sign commit tx
    let signed_commit = bitcoin_client
        .sign_raw_transaction_with_wallet(&commit_tx, None)
        .await
        .unwrap()
        .hex;

    let signed_commit: Transaction = consensus::encode::deserialize_hex(&signed_commit)
        .expect("could not deserialize transaction");

    publish_txs(bitcoin_client, signed_commit, reveal_tx).await?;
    Ok((commit_txid, reveal_txid))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network};
    use bitcoind_async_client::traits::Reader;
    use corepc_node::{serde_json::Value, Conf, Node};
    use strata_l1tx::{envelope::parser::parse_envelope_payloads, TxFilterConfig};
    use strata_primitives::{
        batch::{verify_signed_checkpoint_sig, Checkpoint, SignedCheckpoint},
        buf::Buf32,
        l1::{payload::L1PayloadType, OutputRef},
    };
    use strata_state::{bridge_state::DepositEntry, chain_state::Chainstate};

    use crate::{
        create_and_publish_checkpoint, create_bitcoin_client, create_envelope_params,
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
        let dep1 = DepositEntry::new(0, oref1, vec![1, 2, 3], tenbtc, None);
        let dep2 = DepositEntry::new(1, oref2, vec![1, 2, 3], tenbtc, None);
        let dep3 = DepositEntry::new(2, oref3, vec![1, 2, 3], tenbtc, None);
        let dep4 = DepositEntry::new(3, oref4, vec![1, 2, 3], tenbtc, None);
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
        let (user, password) = node
            .params
            .get_cookie_values()
            .unwrap()
            .map(|c| (c.user, c.password))
            .unwrap_or(("".to_string(), "".to_string()));
        let seq_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        Args {
            bitcoin_url: format!("http://{}", node.params.rpc_socket),
            bitcoin_username: user,
            bitcoin_password: password,
            fee_rate: 100,
            sequencer_address: Address::from_str(seq_addr).unwrap().assume_checked(),
            network: Network::Regtest,
            da_tag: "alpn_da".to_string(),
            checkpoint_tag: "alpn_ckpt".to_string(),
            sequencer_private_key: [1u8; 32].into(),
            deposit_entries: Vec::new(),
        }
    }

    async fn create_and_publish_test_checkpoint(
        env_params: &strata_btcio::writer::builder::EnvelopeParams,
        bitcoin_client: &bitcoind_async_client::Client,
        chainstate: Chainstate,
        seq_privkey: &Buf32,
    ) -> (bitcoin::Txid, bitcoin::Txid) {
        create_and_publish_checkpoint(env_params, bitcoin_client, chainstate, seq_privkey)
            .await
            .inspect_err(|e| println!("Error creating/publishing checkpoint: {e}"))
            .unwrap()
    }

    async fn fetch_and_parse_reveal_tx(
        bitcoin_client: &bitcoind_async_client::Client,
        rtxid: &bitcoin::Txid,
        env_params: &strata_btcio::writer::builder::EnvelopeParams,
    ) -> SignedCheckpoint {
        let tx = bitcoin_client
            .get_raw_transaction_verbosity_zero(rtxid)
            .await
            .unwrap()
            .transaction()
            .unwrap();
        let scr = tx.input[0]
            .witness
            .taproot_leaf_script()
            .unwrap()
            .script
            .to_bytes();

        let filter_conf = TxFilterConfig::derive_from(env_params.params.rollup()).unwrap();
        let checkpoint_payload = parse_envelope_payloads(&scr.into(), &filter_conf)
            .unwrap()
            .into_iter()
            .find(|p| *p.payload_type() == L1PayloadType::Checkpoint)
            .expect("Did not find checpoint in payload");

        borsh::from_slice::<SignedCheckpoint>(checkpoint_payload.data()).unwrap()
    }

    fn verify_checkpoint_and_chainstate(
        signed_checkpoint: &SignedCheckpoint,
        env_params: &strata_btcio::writer::builder::EnvelopeParams,
        expected_chainstate: &Chainstate,
    ) {
        let cred_rule = &env_params.params.rollup().cred_rule;
        assert!(
            verify_signed_checkpoint_sig(signed_checkpoint, cred_rule),
            "Checkpoint verification failed"
        );
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
        let env_params = create_envelope_params(&args);
        let bitcoin_client = create_bitcoin_client(&args);

        let chainstate = ChainstateWithEmptyDeposits::new();
        let dep_entries = create_dep_entries();
        let chainstate = update_deposit_entries(chainstate, &dep_entries);

        let (_ctxid, rtxid) = create_and_publish_test_checkpoint(
            &env_params,
            &bitcoin_client,
            chainstate.clone(),
            &args.sequencer_private_key,
        )
        .await;

        let _ = nodeclient
            .call::<Value>("generatetoaddress", &[1.into(), seq_addr.into()])
            .unwrap();

        let signed_checkpoint =
            fetch_and_parse_reveal_tx(&bitcoin_client, &rtxid, &env_params).await;
        verify_checkpoint_and_chainstate(&signed_checkpoint, &env_params, &chainstate);
    }
}
