use std::{collections::HashSet, sync::Arc, time::Duration};

use bitcoin::{
    hashes::{self, Hash},
    key::TapTweak,
    sighash::{Prevouts, SighashCache},
    Address, Amount, Network, OutPoint, TapSighashType, Transaction, TxOut, Txid,
};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use musig2::{KeyAggContext, SecNonce};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{
    schnorr::{self, Signature},
    Keypair, Message, PublicKey, SecretKey, SECP256K1,
};
use strata_bridge_primitives::{
    params::prelude::{ConnectorParams, MIN_RELAY_FEE},
    scripts::prelude::*,
    wots::{Wots256PublicKey, Wots256Signature},
};
use strata_btcio::rpc::{
    error::ClientError,
    traits::{BroadcasterRpc, ReaderRpc, WalletRpc},
    BitcoinClient,
};
use tracing::trace;

pub(super) const CONNECTOR_PARAMS: ConnectorParams = ConnectorParams {
    payout_optimistic_timelock: 100,
    pre_assert_timelock: 200,
    payout_timelock: 100,
};

#[derive(Debug, Clone)]
pub struct Agent {
    keypair: Keypair,

    pub btc_client: Arc<BitcoinClient>,

    pub strata_client: Arc<WsClient>,
}

impl Agent {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        keypair: Keypair,
        btc_url: &str,
        btc_user: &str,
        btc_pass: &str,
        btc_retry_count: Option<u8>,
        btc_retry_interval: Option<u64>,
        strata_url: &str,
        ws_timeout: Duration,
    ) -> Self {
        let btc_client = BitcoinClient::new(
            btc_url.to_string(),
            btc_user.to_string(),
            btc_pass.to_string(),
            btc_retry_count,
            btc_retry_interval,
        )
        .expect("should be able to create bitcoin client");
        let btc_client = Arc::new(btc_client);

        let strata_client = WsClientBuilder::new()
            .request_timeout(ws_timeout)
            .build(strata_url)
            .await
            .expect("should be able to create a strata RPC client");
        let strata_client = Arc::new(strata_client);

        Self {
            keypair,
            btc_client,
            strata_client,
        }
    }

    pub fn sign(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
        input_index: usize,
        witness_type: Option<&TaprootWitness>,
        sighash_type: Option<TapSighashType>,
    ) -> schnorr::Signature {
        let mut sighash_cache = SighashCache::new(tx);
        let msg = create_message_hash(
            &mut sighash_cache,
            Prevouts::All(prevouts),
            witness_type.unwrap_or(&TaprootWitness::Key),
            sighash_type.unwrap_or(TapSighashType::Default),
            input_index,
        )
        .expect("should be able to create message hash");

        SECP256K1.sign_schnorr(&msg, &self.keypair)
    }

    pub fn sign_txid(&self, txid: &Txid) -> Signature {
        let msg = Message::from_digest(txid.to_byte_array());
        SECP256K1.sign_schnorr(&msg, &self.keypair)
    }

    pub async fn wait_and_broadcast(
        &self,
        tx: &Transaction,
        wait_time: Duration,
    ) -> Result<Txid, ClientError> {
        // sleep to confirm parent
        tokio::time::sleep(wait_time).await;

        self.btc_client.send_raw_transaction(tx).await
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey::from_keypair(&self.keypair)
    }

    pub fn taproot_address(&self, network: Network) -> Address {
        let public_key = self.public_key().x_only_public_key().0;

        Address::p2tr_tweaked(public_key.dangerous_assume_tweaked(), network)
    }

    pub async fn select_utxo(
        &self,
        target_amount: Amount,
        reserved_utxos: HashSet<OutPoint>,
    ) -> Option<(Address, OutPoint, Amount, TxOut)> {
        let unspent_utxos = self
            .btc_client
            .get_utxos()
            .await
            .expect("should be able to get unspent utxos");

        let change_address = self
            .btc_client
            .get_new_address()
            .await
            .expect("should get change address");

        let network = self
            .btc_client
            .network()
            .await
            .expect("should get network from node");

        // FIXME: allow selecting multiple UTXOs that sum up to the required amount
        for entry in unspent_utxos {
            let outpoint = OutPoint {
                txid: entry.txid,
                vout: entry.vout,
            };
            if reserved_utxos.contains(&outpoint) {
                // this utxo has already been selected for some other tx
                continue;
            }

            trace!(%entry.amount, %entry.txid, %entry.vout, %entry.confirmations, "checking unspent utxos");
            if entry.amount > target_amount + MIN_RELAY_FEE {
                return Some((
                    change_address,
                    OutPoint {
                        txid: entry.txid,
                        vout: entry.vout,
                    },
                    entry.amount,
                    TxOut {
                        value: entry.amount,
                        script_pubkey: entry
                            .address
                            .require_network(network)
                            .expect("address should be valid")
                            .script_pubkey(),
                    },
                ));
            }
        }

        None
    }

    /// Generate a random secret nonce.
    ///
    /// Please refer to MuSig2 nonce generation section in
    /// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
    ///
    /// # Notes
    ///
    /// The entropy is pooled using the underlying operating system's
    /// cryptographic-safe pseudo-random number generator with [`OsRng`].
    pub fn generate_sec_nonce(&self, txid: &Txid, key_agg_ctx: &KeyAggContext) -> SecNonce {
        let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

        let mut nonce_seed = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_seed);

        let seckey = SecretKey::from_keypair(&self.keypair);

        SecNonce::build(nonce_seed)
            .with_seckey(seckey)
            .with_message(txid.as_byte_array())
            .with_aggregated_pubkey(aggregated_pubkey)
            .build()
    }

    /// Generates pseudo-random bytes that can be used as preimages deterministically.
    pub fn generate_preimage(&self, seed: &str, stake_index: u32) -> [u8; 32] {
        let data = stake_index.to_be_bytes();
        *hashes::sha256::Hash::hash(&[seed.as_bytes(), &data].concat()).as_byte_array()
    }

    /// Generates the withdrawal fulfillment pk for a given stake transaction index.
    pub fn generate_withdrawal_fulfillment_pk(
        &self,
        seed: &str,
        stake_index: u32,
    ) -> Wots256PublicKey {
        let hash = hashes::sha256::Hash::hash(&stake_index.to_be_bytes());
        let hash = hash.as_byte_array();
        let txid = Txid::from_slice(hash).expect("should be able to create txid from hash");

        Wots256PublicKey::new(seed, txid)
    }

    /// Generates the withdrawal fulfillment signature for a given stake transaction index.
    pub fn generate_withdrawal_fulfillment_signature(
        &self,
        seed: &str,
        stake_index: u32,
        withdrawal_fulfillment_txid: Txid,
    ) -> Wots256Signature {
        let hash = hashes::sha256::Hash::hash(&stake_index.to_be_bytes());
        let hash = hash.as_byte_array();
        let txid = Txid::from_slice(hash).expect("should be able to create txid from hash");

        Wots256Signature::new(seed, txid, withdrawal_fulfillment_txid.as_byte_array())
    }
}
