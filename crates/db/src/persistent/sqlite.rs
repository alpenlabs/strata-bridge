use std::{
    collections::{BTreeMap, HashSet},
    ops::Deref,
    str::FromStr,
};

use async_trait::async_trait;
use bitcoin::{consensus, Network, OutPoint, Transaction, TxOut, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use secp256k1::schnorr::Signature;
use sqlx::{Sqlite, SqlitePool};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, duties::BridgeDutyStatus, scripts::wots, types::OperatorIdx,
};

use super::{
    errors::StorageError,
    types::{
        DbAmount, DbOperatorId, DbPartialSig, DbScriptBuf, DbSecNonce, DbSignature, DbTxid,
        DbWotsPublicKeys, DbWotsSignatures, JoinedKickoffInfo,
    },
};
use crate::{
    errors::DbResult,
    operator::{KickoffInfo, MsgHashAndOpIdToSigMap, OperatorDb},
    persistent::types::DbPubNonce,
    public::PublicDb,
    tracker::{BitcoinBlockTrackerDb, DutyTrackerDb},
};

#[derive(Debug, Clone)]
pub struct SqliteDb {
    pool: SqlitePool,
}

impl SqliteDb {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PublicDb for SqliteDb {
    async fn get_wots_public_keys(
        &self,
        operator_id: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<wots::PublicKeys> {
        let (public_keys, ): (DbWotsPublicKeys, ) = sqlx::query_as(
            r#"SELECT public_keys FROM wots_public_keys WHERE operator_id = $1 AND deposit_txid = $2"#,
        )
        .bind(operator_id)
        .bind(DbTxid::from(deposit_txid))
        .fetch_one(&self.pool)
        .await.map_err(StorageError::from)?;

        Ok(*public_keys)
    }

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO wots_public_keys (operator_id, deposit_txid, public_keys) VALUES ($1, $2, $3)",
        )
        .bind(operator_id)
        .bind(DbTxid::from(deposit_txid))
        .bind(DbWotsPublicKeys::from(*public_keys))
        .execute(&mut *tx)
        .await.map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<wots::Signatures> {
        let (wots_signatures, ): (DbWotsSignatures,) = sqlx::query_as(
            r#"SELECT signatures FROM wots_signatures WHERE operator_id = $1 AND deposit_txid = $2"#,
        )
        .bind(operator_id)
        .bind(DbTxid::from(deposit_txid))
        .fetch_one(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(*wots_signatures)
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO wots_signatures (operator_id, deposit_txid, signatures) VALUES ($1, $2, $3)",
        )
        .bind(operator_id)
        .bind(DbTxid::from(deposit_txid))
        .bind(DbWotsSignatures::from(*signatures))
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Signature> {
        let (signature,): (DbSignature,) = sqlx::query_as(
            "SELECT signature FROM signatures WHERE operator_id = $1 AND txid = $2 AND input_index = $3",
        )
        .bind(operator_idx)
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .fetch_one(&self.pool)
        .await.map_err(StorageError::from)?;

        Ok(*signature)
    }

    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO signatures (signature, operator_id, txid, input_index) VALUES ($1, $2, $3, $4)",
        )
        .bind(DbSignature::from(signature))
        .bind(operator_id)
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .execute(&mut *tx)
        .await.map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO claim_txid_to_operator_index_and_deposit_txid (claim_txid, operator_id, deposit_txid) VALUES ($1, $2, $3)",
        )
        .bind(DbTxid::from(claim_txid))
        .bind(operator_idx)
        .bind(DbTxid::from(deposit_txid))
        .execute(&mut *tx)
        .await.map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbOperatorId, DbTxid)>(
            "SELECT operator_id, deposit_txid FROM claim_txid_to_operator_index_and_deposit_txid WHERE claim_txid = $1",
            )
            .bind(DbTxid::from(*claim_txid))
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?.map(|(id, txid)| (*id, *txid))
        )
    }

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO post_assert_txid_to_operator_index_and_deposit_txid (post_assert_txid, operator_id, deposit_txid) VALUES ($1, $2, $3)",
        )
        .bind(DbTxid::from(post_assert_txid))
        .bind(operator_idx)
        .bind(DbTxid::from(deposit_txid))
        .execute(&mut *tx)
        .await.map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbOperatorId, DbTxid)>(
                "SELECT operator_id, deposit_txid FROM post_assert_txid_to_operator_index_and_deposit_txid WHERE post_assert_txid = $1",
            )
            .bind(DbTxid::from(*post_assert_txid))
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?.map(|(id, txid)| (*id, *txid))
        )
    }

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; 7],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        for txid in assert_data_txids.iter() {
            sqlx::query(
                "INSERT OR REPLACE INTO assert_data_txid_to_operator_and_deposit (assert_data_txid, operator_id, deposit_txid) VALUES ($1, $2, $3)",
            )
                .bind(DbTxid::from(*txid))
                .bind(operator_idx)
                .bind(DbTxid::from(deposit_txid))
            .execute(&mut *tx)
            .await.map_err(StorageError::from)?;
        }

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbOperatorId, DbTxid)>(
                "SELECT operator_id, deposit_txid FROM assert_data_txid_to_operator_and_deposit WHERE assert_data_txid = ?",
            )
            .bind(DbTxid::from(*assert_data_txid))
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|(id, txid)| (*id, *txid))
        )
    }

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO pre_assert_txid_to_operator_and_deposit (pre_assert_data_txid, operator_id, deposit_txid) VALUES (?, ?, ?)",
        )
        .bind(DbTxid::from(pre_assert_data_txid))
        .bind(operator_idx)
        .bind(DbTxid::from(deposit_txid))
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbOperatorId, DbTxid)>(
                "SELECT operator_id, deposit_txid FROM pre_assert_txid_to_operator_and_deposit WHERE pre_assert_data_txid = $1",
            )
            .bind(DbTxid::from(*pre_assert_data_txid))
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|(id, txid)| (*id, *txid))
        )
    }
}

#[async_trait]
impl OperatorDb for SqliteDb {
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO collected_pubnonces (txid, input_index, operator_id, pubnonce) VALUES ($1, $2, $3, $4)",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .bind(DbOperatorId::from(operator_idx))
        .bind(DbPubNonce::from(pubnonce))
        .execute(&mut *tx)
        .await.map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<BTreeMap<OperatorIdx, PubNonce>>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbOperatorId, DbPubNonce)>(
            "SELECT operator_id, pubnonce FROM collected_pubnonces WHERE txid = $1 AND input_index = $2",
            )
            .bind(DbTxid::from(txid))
            .bind(input_index)
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::from)?
            .into_iter()
            .map(|(id, pubnonce)| Some((*id, pubnonce.deref().clone())))
            .collect()
        )
    }

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO sec_nonces (txid, input_index, sec_nonce) VALUES ($1, $2, $3)",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .bind(DbSecNonce::from(secnonce))
        .execute(&mut *tx)
        .await
        .expect("should be able to add secnonce to db");

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> DbResult<Option<SecNonce>> {
        Ok(sqlx::query_as::<Sqlite, (DbSecNonce,)>(
            "SELECT sec_nonce FROM sec_nonces WHERE txid = $1 AND input_index = $2",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|(secnonce,)| secnonce.deref().clone()))
    }

    // Add or update a message hash and associated partial signature
    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        // Insert or ignore into `collected_messages` to avoid overwriting `msg_hash`
        sqlx::query(
            "INSERT OR IGNORE INTO collected_messages (txid, input_index, msg_hash) VALUES ($1, $2, $3)",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .bind(message_sighash)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        // Insert or replace the partial signature in `collected_signatures`
        sqlx::query(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES ($1, $2, $3, $4)",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .bind(operator_idx)
        .bind(DbPartialSig::from(signature))
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    // Add or update a partial signature for an existing `(txid, input_index, operator_id)`
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES ($1, $2, $3, $4)",
        )
        .bind(DbTxid::from(txid))
        .bind(input_index)
        .bind(operator_idx)
        .bind(DbPartialSig::from(signature))
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(())
    }

    // Fetch all collected signatures for a given `(txid, input_index)`, along with the message hash
    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<MsgHashAndOpIdToSigMap>> {
        // Fetch `msg_hash` from `collected_messages` and associated signatures from
        // `collected_signatures`
        Ok(
            sqlx::query_as::<Sqlite, (Vec<u8>, DbOperatorId, DbPartialSig)>(
                "SELECT m.msg_hash, s.operator_id, s.partial_signature
                FROM collected_messages m
                JOIN collected_signatures s ON m.txid = s.txid AND m.input_index = s.input_index
                WHERE m.txid = $1 AND m.input_index = $2",
            )
            .bind(DbTxid::from(txid))
            .bind(input_index)
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::from)?
            .chunk_by(|a, b| a.0 == b.0)
            .map(|v| {
                let msg_hash = v[0].0.clone();
                let op_id_to_sig_map = v
                    .iter()
                    .map(|(_, operator_id, signature)| (**operator_id, **signature))
                    .collect();

                (msg_hash, op_id_to_sig_map)
            })
            .next(),
        )
    }

    async fn add_outpoint(&self, outpoint: OutPoint) -> DbResult<bool> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let result =
            sqlx::query("INSERT OR IGNORE INTO selected_outpoints (txid, vout) VALUES (?, ?)")
                .bind(DbTxid::from(outpoint.txid))
                .bind(outpoint.vout)
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(result.rows_affected() > 0)
    }

    async fn selected_outpoints(&self) -> DbResult<HashSet<OutPoint>> {
        Ok(
            sqlx::query_as::<Sqlite, (DbTxid, u32)>("SELECT txid, vout FROM selected_outpoints")
                .fetch_all(&self.pool)
                .await
                .map_err(StorageError::from)?
                .into_iter()
                .map(|(txid, vout)| OutPoint { txid: *txid, vout })
                .collect(),
        )
    }

    async fn add_kickoff_info(
        &self,
        deposit_txid: Txid,
        kickoff_info: KickoffInfo,
    ) -> DbResult<()> {
        let change_address = kickoff_info.change_address.address().to_string();
        let change_address_network = kickoff_info.change_address.network().to_string();

        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO kickoff_info (txid, change_address, change_address_network, change_amount) VALUES ($1, $2, $3, $4)",
        )
            .bind(DbTxid::from(deposit_txid))
            .bind(change_address)
            .bind(change_address_network)
            .bind(DbAmount::from(kickoff_info.change_amt))
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        for input in kickoff_info.funding_inputs {
            sqlx::query(
                "INSERT INTO funding_inputs (kickoff_txid, input_txid, vout) VALUES ($1, $2, $3)",
            )
            .bind(DbTxid::from(deposit_txid))
            .bind(DbTxid::from(input.txid))
            .bind(input.vout)
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        for utxo in kickoff_info.funding_utxos {
            sqlx::query(
                "INSERT INTO funding_utxos (kickoff_txid, value, script_pubkey) VALUES ($1, $2, $3)",
            )
            .bind(DbTxid::from(deposit_txid))
            .bind(DbAmount::from(utxo.value))
            .bind(DbScriptBuf::from(utxo.script_pubkey))
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> DbResult<Option<KickoffInfo>> {
        // Query to retrieve KickoffInfo, funding inputs, and funding UTXOs in a single query
        let rows = sqlx::query_as::<Sqlite, JoinedKickoffInfo>(
            r#"
        SELECT
            ki.txid AS "ki_txid!",
            ki.change_address AS "ki_change_address!",
            ki.change_address_network AS "ki_change_address_network!",
            ki.change_amount AS "ki_change_amount!",
            fi.input_txid AS "fi_input_txid?",
            fi.vout AS "fi_vout?",
            fu.value AS "fu_value?",
            fu.script_pubkey AS "fu_script_pubkey?"
        FROM kickoff_info ki
        LEFT JOIN funding_inputs fi ON fi.kickoff_txid = ki.txid
        LEFT JOIN funding_utxos fu ON fu.kickoff_txid = ki.txid
        WHERE ki.txid = $1
        "#,
        )
        .bind(DbTxid::from(deposit_txid))
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.is_empty() {
            return Ok(None);
        }

        // Initialize `KickoffInfo` fields from the first row
        let first_row = &rows[0];

        let change_network = Network::from_str(&first_row.ki_change_address_network)
            .map_err(|e| StorageError::MismatchedTypes(e.to_string()))?;
        let change_address = BitcoinAddress::parse(&first_row.ki_change_address, change_network)
            .map_err(|e| StorageError::MismatchedTypes(e.to_string()))?;

        let change_amt = *first_row.ki_change_amount;

        // Iterate through all rows to populate funding_inputs and funding_utxos
        let (funding_utxos, funding_inputs) = rows
            .into_iter()
            .filter_map(|row| {
                match (
                    row.fi_input_txid,
                    row.fi_vout,
                    row.fu_value,
                    row.fu_script_pubkey,
                ) {
                    (Some(input_txid), Some(vout), Some(value), Some(script_pubkey)) => {
                        let txid = *input_txid;
                        let value = *value;
                        let script_pubkey = script_pubkey.deref().clone();

                        Some((
                            TxOut {
                                value,
                                script_pubkey,
                            },
                            OutPoint { txid, vout },
                        ))
                    }
                    _ => None,
                }
            })
            .unzip();

        Ok(Some(KickoffInfo {
            change_address,
            change_amt,
            funding_inputs,
            funding_utxos,
        }))
    }

    async fn get_checkpoint_index(&self, deposit_txid: Txid) -> DbResult<Option<u64>> {
        Ok(sqlx::query_as::<Sqlite, (u64,)>(
            "SELECT checkpoint_idx FROM strata_checkpoint WHERE txid = $1",
        )
        .bind(DbTxid::from(deposit_txid))
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|v| v.0))
    }

    async fn set_checkpoint_index(
        &self,
        deposit_txid: Txid,
        checkpoint_index: u64,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query(
            "INSERT OR REPLACE INTO strata_checkpoint (txid, checkpoint_idx) VALUES (?, ?)",
        )
        .bind(DbTxid::from(deposit_txid))
        .bind(checkpoint_index as i64)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }
}

#[async_trait]
impl DutyTrackerDb for SqliteDb {
    async fn get_last_fetched_duty_index(&self) -> u64 {
        // Retrieve last fetched duty index from duty_index_tracker table
        let row =
            sqlx::query!("SELECT last_fetched_duty_index FROM duty_index_tracker WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .expect("Failed to fetch last fetched duty index");

        row.map(|r| r.last_fetched_duty_index as u64).unwrap_or(0) // Default to 0 if no record
    }

    async fn set_last_fetched_duty_index(&self, duty_index: u64) {
        let duty_index = duty_index as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_index_tracker (id, last_fetched_duty_index) VALUES (1, ?)",
            duty_index
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to set the last fetched duty index");

        tx.commit()
            .await
            .expect("should be able to commit last fetch duty index");
    }

    async fn fetch_duty_status(&self, duty_id: Txid) -> Option<BridgeDutyStatus> {
        let duty_id = consensus::encode::serialize_hex(&duty_id);
        let row = sqlx::query!("SELECT status FROM duty_tracker WHERE duty_id = ?", duty_id)
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to fetch duty status");

        row.map(|r| serde_json::from_str(&r.status).expect("Failed to parse duty status JSON"))
    }

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) {
        let duty_id = consensus::encode::serialize_hex(&duty_id);
        let status_json =
            serde_json::to_string(&status).expect("Failed to serialize duty status to JSON");

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_tracker (duty_id, status) VALUES (?, ?)",
            duty_id,
            status_json
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to update duty status");

        tx.commit()
            .await
            .expect("should be able to commit duty status");
    }
}

#[async_trait]
impl BitcoinBlockTrackerDb for SqliteDb {
    async fn get_last_scanned_block_height(&self) -> u64 {
        let row = sqlx::query!("SELECT block_height FROM bitcoin_block_index_tracker WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to fetch last scanned block height");

        row.map(|r| r.block_height as u64).unwrap_or(0) // Default to 0 if no record
    }

    async fn set_last_scanned_block_height(&self, block_height: u64) {
        let block_height = block_height as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_block_index_tracker (id, block_height) VALUES (1, ?)",
            block_height
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert last scanned block height");

        tx.commit()
            .await
            .expect("should be able to commit last scanned block height");
    }

    async fn get_relevant_tx(&self, txid: &Txid) -> Option<Transaction> {
        let txid = consensus::encode::serialize_hex(txid);

        let row = sqlx::query!("SELECT tx FROM bitcoin_tx_index WHERE txid = ?", txid)
            .fetch_optional(&self.pool)
            .await
            .expect("should be able to fetch tx from db");

        row.map(|btc_tx| {
            consensus::encode::deserialize_hex(&btc_tx.tx)
                .expect("should be able to deserialize transaction")
        })
    }

    async fn add_relevant_tx(&self, tx: Transaction) {
        let txid = tx.compute_txid();
        let txid = consensus::encode::serialize_hex(&txid);
        let tx = consensus::encode::serialize_hex(&tx);

        let mut sqlx_tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_tx_index (txid, tx) VALUES (?, ?)",
            txid,
            tx
        )
        .execute(&mut *sqlx_tx)
        .await
        .expect("should be able to insert relevant tx to db");

        sqlx_tx
            .commit()
            .await
            .expect("should be able to commit relevant tx to db");
    }
}
