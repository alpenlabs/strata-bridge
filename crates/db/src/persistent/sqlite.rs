use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use async_trait::async_trait;
use bitcoin::{consensus, hex::DisplayHex, Amount, Network, OutPoint, Transaction, TxOut, Txid};
use musig2::{BinaryEncoding, PartialSignature, PubNonce, SecNonce};
use secp256k1::schnorr::Signature;
use sqlx::{Sqlite, SqlitePool};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, duties::BridgeDutyStatus, scripts::wots, types::OperatorIdx,
};
use tracing::trace;

use super::{
    errors::StorageError,
    types::{DbOperatorId, DbSignature, DbTxid, DbWotsPublicKeys, DbWotsSignatures},
};
use crate::{
    errors::DbResult,
    operator::{KickoffInfo, MsgHashAndOpIdToSigMap, OperatorDb},
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
    ) {
        let txid = consensus::encode::serialize_hex(&txid);
        let pubnonce = pubnonce.to_string();

        trace!(action = "adding pubnonce to db", %txid, %operator_idx);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_pubnonces (txid, input_index, operator_id, pubnonce) VALUES (?, ?, ?, ?)",
            txid,
            input_index,
            operator_idx,
            pubnonce
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert pubnonce into the db");

        tx.commit()
            .await
            .expect("should be able to commit pubnonce");

        trace!(event = "added pubnonce to db", %txid, %operator_idx);
    }

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<BTreeMap<OperatorIdx, PubNonce>> {
        let txid = consensus::encode::serialize_hex(&txid);
        let results = sqlx::query!(
            "SELECT operator_id, pubnonce FROM collected_pubnonces WHERE txid = ? AND input_index = ?",
            txid,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .expect("should be able to fetch pubnonce from the db");

        if results.is_empty() {
            None
        } else {
            Some(
                results
                    .into_iter()
                    .map(|record| {
                        (
                            record.operator_id as OperatorIdx,
                            PubNonce::from_str(&record.pubnonce)
                                .expect("pubnonce format should be valid"),
                        )
                    })
                    .collect(),
            )
        }
    }

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) {
        let txid = consensus::encode::serialize_hex(&txid);
        let secnonce = secnonce.to_bytes().to_vec();

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        sqlx::query!(
            "INSERT OR REPLACE INTO sec_nonces (txid, input_index, sec_nonce) VALUES (?, ?, ?)",
            txid,
            input_index,
            secnonce,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to add secnonce to db");

        tx.commit()
            .await
            .expect("should be able to commit secnonce into the db")
    }

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> Option<SecNonce> {
        let txid = consensus::encode::serialize_hex(&txid);

        let result = sqlx::query!(
            "SELECT sec_nonce FROM sec_nonces WHERE txid = ? AND input_index = ?",
            txid,
            input_index
        )
        .fetch_optional(&self.pool)
        .await
        .expect("should be able to fetch secnonce from the db");

        result
            .map(|record| SecNonce::from_bytes(&record.sec_nonce).expect("Invalid SecNonce format"))
    }

    // Add or update a message hash and associated partial signature
    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let txid_str = consensus::encode::serialize_hex(&txid);
        let partial_signature = signature.serialize().to_lower_hex_string();

        trace!(msg = "adding own partial signature", %txid_str, %input_index, %operator_idx, %partial_signature);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        // Insert or ignore into `collected_messages` to avoid overwriting `msg_hash`
        sqlx::query!(
            "INSERT OR IGNORE INTO collected_messages (txid, input_index, msg_hash) VALUES (?, ?, ?)",
            txid_str,
            input_index,
            message_sighash
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert or ignore message entry");

        // Insert or replace the partial signature in `collected_signatures`
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES (?, ?, ?, ?)",
            txid_str,
            input_index,
            operator_idx,
            partial_signature
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert or replace partial signature");

        tx.commit()
            .await
            .expect("should be able to commit message hash and signature");
    }

    // Add or update a partial signature for an existing `(txid, input_index, operator_id)`
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let txid_str = consensus::encode::serialize_hex(&txid);
        let partial_signature = signature.serialize().to_lower_hex_string();

        trace!(msg = "adding collected partial signature", %txid_str, %input_index, %operator_idx, %partial_signature);

        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures (txid, input_index, operator_id, partial_signature)
            VALUES (?, ?, ?, ?)",
            txid_str,
            input_index,
            operator_idx,
            partial_signature
        )
        .execute(&self.pool)
        .await
        .expect("should be able to insert or replace partial signature");
    }

    // Fetch all collected signatures for a given `(txid, input_index)`, along with the message hash
    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<MsgHashAndOpIdToSigMap> {
        // Convert `txid` to a hex string for querying
        let txid_str = consensus::encode::serialize_hex(&txid);
        trace!(msg = "getting collected signatures", %txid_str, %input_index);

        // Fetch `msg_hash` from `collected_messages` and associated signatures from
        // `collected_signatures`
        let results = sqlx::query!(
            "SELECT m.msg_hash, s.operator_id, s.partial_signature
            FROM collected_messages m
            JOIN collected_signatures s ON m.txid = s.txid AND m.input_index = s.input_index
            WHERE m.txid = ? AND m.input_index = ?",
            txid_str,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .expect("Failed to fetch collected signatures");

        // Return None if no results are found
        if results.is_empty() {
            None
        } else {
            // Use the first record's `msg_hash` and initialize the BTreeMap for signatures
            let msg_hash = results[0].msg_hash.clone();
            let mut op_id_to_sig_map = BTreeMap::new();

            for record in results {
                let operator_id = record.operator_id as OperatorIdx;
                let signature = PartialSignature::from_str(&record.partial_signature)
                    .expect("Invalid signature format");

                let signature_str = signature.serialize().to_lower_hex_string();
                trace!(action = "getting partial signature", %signature_str, %txid, %input_index, %operator_id);

                op_id_to_sig_map.insert(operator_id, signature);
            }

            Some((msg_hash, op_id_to_sig_map))
        }
    }

    async fn add_outpoint(&self, outpoint: OutPoint) -> bool {
        let txid = consensus::encode::serialize_hex(&outpoint.txid);

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");
        let result = sqlx::query!(
            "INSERT OR IGNORE INTO selected_outpoints (txid, vout) VALUES (?, ?)",
            txid,
            outpoint.vout,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert outpoint");

        tx.commit()
            .await
            .expect("should be able to commit outpoint");

        result.rows_affected() > 0
    }

    async fn selected_outpoints(&self) -> HashSet<OutPoint> {
        let results = sqlx::query!("SELECT txid, vout FROM selected_outpoints")
            .fetch_all(&self.pool)
            .await
            .expect("Failed to fetch selected outpoints");

        results
            .into_iter()
            .map(|record| OutPoint {
                txid: consensus::encode::deserialize_hex(&record.txid)
                    .expect("should be able to deserialize outpoint txid"),
                vout: record.vout as u32,
            })
            .collect()
    }

    async fn add_kickoff_info(&self, deposit_txid: Txid, kickoff_info: KickoffInfo) {
        let deposit_txid = consensus::encode::serialize_hex(&deposit_txid);
        let change_address = kickoff_info.change_address.address().to_string();
        let change_address_network = kickoff_info.change_address.network().to_string();
        let change_amount = kickoff_info.change_amt.to_sat() as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO kickoff_info (txid, change_address, change_address_network, change_amount) VALUES (?, ?, ?, ?)",
            deposit_txid,
            change_address,
            change_address_network,
            change_amount,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert kickoff info");

        for input in kickoff_info.funding_inputs {
            let input_txid = consensus::encode::serialize_hex(&input.txid);
            sqlx::query!(
                "INSERT INTO funding_inputs (kickoff_txid, input_txid, vout) VALUES (?, ?, ?)",
                deposit_txid,
                input_txid,
                input.vout
            )
            .execute(&mut *tx)
            .await
            .expect("should be able to insert funding input");
        }

        for utxo in kickoff_info.funding_utxos {
            let utxo_value = utxo.value.to_sat() as i64;
            let utxo_script_pubkey = consensus::encode::serialize_hex(&utxo.script_pubkey);

            sqlx::query!(
                "INSERT INTO funding_utxos (kickoff_txid, value, script_pubkey) VALUES (?, ?, ?)",
                deposit_txid,
                utxo_value,
                utxo_script_pubkey,
            )
            .execute(&mut *tx)
            .await
            .expect("should be able to insert funding utxo");
        }

        tx.commit()
            .await
            .expect("should be able to commit kickoff info");
    }

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> Option<KickoffInfo> {
        // Convert Txid to string format
        let txid_str = consensus::encode::serialize_hex(&deposit_txid);

        // Query to retrieve KickoffInfo, funding inputs, and funding UTXOs in a single query
        let rows = sqlx::query!(
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
        WHERE ki.txid = ?
        "#,
            txid_str
        )
        .fetch_all(&self.pool)
        .await
        .expect("Failed to fetch kickoff_info with joins");

        if rows.is_empty() {
            return None;
        }

        // Initialize `KickoffInfo` fields from the first row
        let first_row = &rows[0];
        let change_network = Network::from_str(&first_row.ki_change_address_network)
            .expect("network should be valid");
        let change_address = BitcoinAddress::parse(&first_row.ki_change_address, change_network)
            .expect("address and network must be compatible");
        let change_amt = Amount::from_sat(first_row.ki_change_amount as u64);

        let mut funding_inputs = Vec::new();
        let mut funding_utxos = Vec::new();

        // Iterate through all rows to populate funding_inputs and funding_utxos
        for row in rows {
            // Process funding input
            if let (Some(input_txid), Some(vout)) = (&row.fi_input_txid, row.fi_vout) {
                funding_inputs.push(OutPoint {
                    txid: consensus::encode::deserialize_hex(input_txid)
                        .expect("should be able to deserialize input txid"),
                    vout: vout as u32,
                });
            }

            // Process funding UTXO
            if let (Some(value), Some(script_pubkey)) = (row.fu_value, &row.fu_script_pubkey) {
                let script_pubkey = consensus::encode::deserialize_hex(script_pubkey)
                    .expect("should be able to deserialize script pubkey in db");

                let value = Amount::from_sat(value as u64);

                funding_utxos.push(TxOut {
                    value,
                    script_pubkey,
                });
            }
        }

        Some(KickoffInfo {
            change_address,
            change_amt,
            funding_inputs,
            funding_utxos,
        })
    }

    async fn get_checkpoint_index(&self, deposit_txid: Txid) -> Option<u64> {
        let txid = consensus::encode::serialize_hex(&deposit_txid);

        let record = sqlx::query!(
            "SELECT checkpoint_idx FROM strata_checkpoint WHERE txid = ?",
            txid,
        )
        .fetch_optional(&self.pool)
        .await
        .expect("should be able to get checkpoint index from the db");

        record.map(|v| v.checkpoint_idx as u64)
    }

    async fn set_checkpoint_index(&self, deposit_txid: Txid, checkpoint_index: u64) {
        let txid = consensus::encode::serialize_hex(&deposit_txid);
        let checkpoint_index = checkpoint_index as i64;

        let mut tx = self
            .pool
            .begin()
            .await
            .expect("should be able to start a transaction");

        sqlx::query!(
            "INSERT OR REPLACE INTO strata_checkpoint (txid, checkpoint_idx) VALUES (?, ?)",
            txid,
            checkpoint_index,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to insert checkpoint index into db");

        tx.commit()
            .await
            .expect("should be able to commit checkpoint index");
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
