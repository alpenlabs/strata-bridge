use alloy::primitives::Address as EvmAddress;
use anyhow::{Context, Result};
use bitcoin::{address::Address, taproot::TapNodeHash, Network};
use bitcoincore_rpc::{
    json::{
        CreateRawTransactionInput, WalletCreateFundedPsbtOptions, WalletCreateFundedPsbtResult,
    },
    Client, RpcApi,
};
use tracing::{debug, info};

use crate::{bridge_in::deposit_request::*, constants::AMOUNT};

pub(crate) trait PsbtWallet {
    fn create_psbt(
        &self,
        destination_address: &Address,
        evm_address: &EvmAddress,
        script_hash: &TapNodeHash,
        network: &Network,
    ) -> Result<String>;

    fn sign_and_broadcast_psbt(&self, psbt: &str) -> Result<()>;
}

pub(crate) struct BitcoinRpcWallet {
    client: Client,
}

impl BitcoinRpcWallet {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

impl PsbtWallet for BitcoinRpcWallet {
    fn create_psbt(
        &self,
        destination_address: &Address,
        evm_address: &EvmAddress,
        script_hash: &TapNodeHash,
        network: &Network,
    ) -> Result<String> {
        let op_return_bytes = build_op_return_script(evm_address, script_hash);
        let change_address = self
            .client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .context("Failed to get new address from RPC client")?
            .require_network(*network)
            .context("Failed to get change address");

        let inputs: Vec<CreateRawTransactionInput> = vec![];
        let outputs = vec![
            serde_json::Map::from_iter(vec![(
                destination_address.to_string(),
                serde_json::to_value(AMOUNT.to_btc())?,
            )]),
            serde_json::Map::from_iter(vec![(
                "data".to_string(),
                serde_json::to_value(hex::encode(op_return_bytes))?,
            )]),
        ];

        let options = WalletCreateFundedPsbtOptions {
            replaceable: Some(true),
            change_address: Some(change_address.unwrap().as_unchecked().clone()),
            change_position: Some(2),
            ..Default::default()
        };

        let args: Vec<serde_json::Value> = vec![
            serde_json::to_value(inputs)?,
            serde_json::to_value(outputs)?,
            serde_json::Value::Null,
            serde_json::to_value(options)?,
            serde_json::Value::Null,
        ];

        let psbt: WalletCreateFundedPsbtResult =
            self.client.call("walletcreatefundedpsbt", &args)?;
        Ok(psbt.psbt)
    }

    fn sign_and_broadcast_psbt(&self, psbt: &str) -> Result<()> {
        let signed_psbt = self
            .client
            .wallet_process_psbt(psbt, None, None, None)
            .context("Failed to process psbt")?;
        let finalized_psbt = self.client.finalize_psbt(&signed_psbt.psbt, None).unwrap();

        let tx = finalized_psbt.transaction();
        debug!(event = "finalized psbt", ?tx);

        let raw_tx = finalized_psbt.hex.unwrap();
        let txid = self.client.send_raw_transaction(&raw_tx).unwrap();
        info!(event = "transaction broadcasted with txid", %txid);

        Ok(())
    }
}
