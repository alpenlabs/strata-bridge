//! SQLite implementation of the persistent storage layer.

use std::{
    collections::{BTreeMap, HashSet},
    ops::Deref,
    str::FromStr,
};

use async_trait::async_trait;
use bitcoin::{Network, OutPoint, Transaction, TxOut, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use secp256k1::schnorr::Signature;
use sqlx::SqlitePool;
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, duties::BridgeDutyStatus, types::OperatorIdx, wots,
};

use super::{
    errors::StorageError,
    types::{
        DbAmount, DbDutyStatus, DbInputIndex, DbPartialSig, DbScriptBuf, DbSecNonce, DbSignature,
        DbTransaction, DbTxid, DbWotsPublicKeys, DbWotsSignatures,
    },
};
use crate::{
    errors::DbResult,
    operator::{KickoffInfo, MsgHashAndOpIdToSigMap, OperatorDb},
    persistent::{models, types::DbPubNonce},
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
    ) -> DbResult<Option<wots::PublicKeys>> {
        let deposit_txid = DbTxid::from(deposit_txid);
        let result = sqlx::query_as!(
            models::WotsPublicKey,
            r#"SELECT
                public_keys as "public_keys: DbWotsPublicKeys",
                operator_id,
                deposit_txid AS "deposit_txid: DbTxid"
                FROM wots_public_keys
                WHERE operator_id = $1 AND deposit_txid = $2"#,
            operator_id,
            deposit_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|v| *v.public_keys);

        Ok(result)
    }

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let deposit_txid = DbTxid::from(deposit_txid);
        let public_keys = DbWotsPublicKeys::from(*public_keys);

        sqlx::query!(
            "INSERT OR REPLACE INTO wots_public_keys
                (operator_id, deposit_txid, public_keys)
                VALUES ($1, $2, $3)",
            operator_id,
            deposit_txid,
            public_keys,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::Signatures>> {
        let deposit_txid = DbTxid::from(deposit_txid);
        let result = sqlx::query_as!(
            models::WotsSignature,
            r#"SELECT signatures AS "signatures: DbWotsSignatures",
                operator_id,
                deposit_txid AS "deposit_txid: DbTxid"
                FROM wots_signatures
                WHERE operator_id = $1 AND deposit_txid = $2"#,
            operator_id,
            deposit_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|v| *v.signatures);

        Ok(result)
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let deposit_txid = DbTxid::from(deposit_txid);
        let db_signatures = DbWotsSignatures::from(*signatures);
        sqlx::query!(
            "INSERT OR REPLACE INTO wots_signatures
                (operator_id, deposit_txid, signatures)
                VALUES ($1, $2, $3)",
            operator_id,
            deposit_txid,
            db_signatures,
        )
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
    ) -> DbResult<Option<Signature>> {
        let txid = DbTxid::from(txid);
        let result = sqlx::query_as!(
            models::Signature,
            r#"SELECT
                signature AS "signature: DbSignature",
                operator_id,
                txid AS "txid: DbTxid",
                input_index
                FROM signatures
                WHERE operator_id = $1 AND txid = $2 AND input_index = $3"#,
            operator_idx,
            txid,
            input_index,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|v| *v.signature);

        Ok(result)
    }

    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let signature = DbSignature::from(signature);
        let txid = DbTxid::from(txid);
        sqlx::query!(
            "INSERT OR REPLACE INTO signatures (signature, operator_id, txid, input_index) VALUES ($1, $2, $3, $4)",
            signature,
            operator_id,
            txid,
            input_index
        )
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

        let claim_txid = DbTxid::from(claim_txid);
        let deposit_txid = DbTxid::from(deposit_txid);
        sqlx::query!(
            "INSERT OR REPLACE INTO claim_txid_to_operator_index_and_deposit_txid
                (claim_txid, operator_id, deposit_txid)
                VALUES ($1, $2, $3)",
            claim_txid,
            operator_idx,
            deposit_txid,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        let claim_txid = DbTxid::from(*claim_txid);
        Ok(sqlx::query_as!(
            models::ClaimToOperatorAndDeposit,
            r#"SELECT
                    operator_id,
                    deposit_txid AS "deposit_txid!: DbTxid",
                    claim_txid AS "claim_txid!: DbTxid"
                    FROM claim_txid_to_operator_index_and_deposit_txid
                    WHERE claim_txid = $1"#,
            claim_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|row| (*row.operator_id, *row.deposit_txid)))
    }

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let post_assert_txid = DbTxid::from(post_assert_txid);
        let deposit_txid = DbTxid::from(deposit_txid);
        sqlx::query!(
            "INSERT OR REPLACE INTO post_assert_txid_to_operator_index_and_deposit_txid
                (post_assert_txid, operator_id, deposit_txid)
                VALUES ($1, $2, $3)",
            post_assert_txid,
            operator_idx,
            deposit_txid,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        let post_assert_txid = DbTxid::from(*post_assert_txid);
        Ok(sqlx::query_as!(
            models::PostAssertToOperatorAndDeposit,
            r#"SELECT
                post_assert_txid AS "post_assert_txid!: DbTxid",
                operator_id,
                deposit_txid AS "deposit_txid!: DbTxid"
                FROM post_assert_txid_to_operator_index_and_deposit_txid
                WHERE post_assert_txid = $1"#,
            post_assert_txid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|row| (*row.operator_id, *row.deposit_txid)))
    }

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; 7],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let deposit_txid = DbTxid::from(deposit_txid);
        for txid in assert_data_txids {
            let assert_data_txid = DbTxid::from(txid);
            sqlx::query!(
                "INSERT OR REPLACE INTO assert_data_txid_to_operator_and_deposit
                    (assert_data_txid, operator_id, deposit_txid)
                    VALUES ($1, $2, $3)",
                assert_data_txid,
                operator_idx,
                deposit_txid,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        let assert_data_txid = DbTxid::from(*assert_data_txid);
        Ok(sqlx::query_as!(
            models::AssertDataToOperatorAndDeposit,
            r#"SELECT
                assert_data_txid AS "assert_data_txid!: DbTxid",
                operator_id,
                deposit_txid AS "deposit_txid!: DbTxid"
                FROM assert_data_txid_to_operator_and_deposit
                WHERE assert_data_txid = ?"#,
            assert_data_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|record| (*record.operator_id, *record.deposit_txid)))
    }

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let pre_assert_data_txid = DbTxid::from(pre_assert_data_txid);
        let deposit_txid = DbTxid::from(deposit_txid);
        sqlx::query!(
            "INSERT OR REPLACE INTO pre_assert_txid_to_operator_and_deposit
                (pre_assert_data_txid, operator_id, deposit_txid)
                VALUES ($1, $2, $3)",
            pre_assert_data_txid,
            operator_idx,
            deposit_txid,
        )
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
        let pre_assert_data_txid = DbTxid::from(*pre_assert_data_txid);
        Ok(sqlx::query_as!(
            models::PreAssertToOperatorAndDeposit,
            r#"SELECT
                pre_assert_data_txid AS "pre_assert_txid!: DbTxid",
                operator_id,
                deposit_txid AS "deposit_txid!: DbTxid"
                FROM pre_assert_txid_to_operator_and_deposit
                WHERE pre_assert_data_txid = $1"#,
            pre_assert_data_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|record| (*record.operator_id, *record.deposit_txid)))
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

        let txid = DbTxid::from(txid);
        let pubnonce = DbPubNonce::from(pubnonce);
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_pubnonces
                (txid, input_index, operator_id, pubnonce)
                VALUES ($1, $2, $3, $4)",
            txid,
            input_index,
            operator_idx,
            pubnonce,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<BTreeMap<OperatorIdx, PubNonce>> {
        let txid = DbTxid::from(txid);
        Ok(sqlx::query_as!(
            models::CollectedPubnonces,
            r#"SELECT
                operator_id,
                pubnonce AS "pubnonce: DbPubNonce",
                txid AS "txid: DbTxid",
                input_index AS "input_index: DbInputIndex"
                FROM collected_pubnonces WHERE txid = $1 AND input_index = $2"#,
            txid,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?
        .into_iter()
        .map(|row| (*row.operator_id, row.pubnonce.deref().clone()))
        .collect())
    }

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let txid = DbTxid::from(txid);
        let secnonce = DbSecNonce::from(secnonce);

        sqlx::query!(
            "INSERT OR REPLACE INTO sec_nonces
                (txid, input_index, sec_nonce)
                VALUES ($1, $2, $3)",
            txid,
            input_index,
            secnonce,
        )
        .execute(&mut *tx)
        .await
        .expect("should be able to add secnonce to db");

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> DbResult<Option<SecNonce>> {
        let txid = DbTxid::from(txid);
        Ok(sqlx::query_as!(
            models::Secnonces,
            r#"SELECT
                txid AS "txid!: DbTxid",
                input_index,
                sec_nonce AS "secnonce!: DbSecNonce"
                FROM sec_nonces
                WHERE txid = $1 AND input_index = $2"#,
            txid,
            input_index
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|row| row.secnonce.deref().clone()))
    }

    // Add or update a message hash and associated partial signature.
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
        let txid = DbTxid::from(txid);
        sqlx::query!(
            "INSERT OR IGNORE INTO collected_messages
                (txid, input_index, msg_hash)
                VALUES ($1, $2, $3)",
            txid,
            input_index,
            message_sighash
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        // Insert or replace the partial signature in `collected_signatures`
        let partial_signature = DbPartialSig::from(signature);
        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures
                (txid, input_index, operator_id, partial_signature)
                VALUES ($1, $2, $3, $4)",
            txid,
            input_index,
            operator_idx,
            partial_signature,
        )
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
        let txid = DbTxid::from(txid);
        let partial_signature = DbPartialSig::from(signature);

        if sqlx::query!(
            "SELECT txid FROM collected_messages
                WHERE txid = $1 AND input_index = $2",
            txid,
            input_index,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .is_none()
        {
            return Err(StorageError::InvalidData(
                "message hash not found".to_string(),
            ))?;
        }

        sqlx::query!(
            "INSERT OR REPLACE INTO collected_signatures
                (txid, input_index, operator_id, partial_signature)
                VALUES ($1, $2, $3, $4)",
            txid,
            input_index,
            operator_idx,
            partial_signature,
        )
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
        let txid = DbTxid::from(txid);
        Ok(sqlx::query_as!(
            models::CollectedSigsPerMsg,
            r#"SELECT
                    m.msg_hash,
                    s.operator_id,
                    s.partial_signature AS "partial_signature: DbPartialSig"
                    FROM collected_messages m
                    JOIN collected_signatures s ON m.txid = s.txid AND m.input_index = s.input_index
                    WHERE m.txid = $1 AND m.input_index = $2"#,
            txid,
            input_index
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?
        .chunk_by(|a, b| a.msg_hash == b.msg_hash)
        .map(|v| {
            let msg_hash = v[0].msg_hash.clone();
            let op_id_to_sig_map = v
                .iter()
                .map(|row| (*row.operator_id, *row.partial_signature))
                .collect();

            (msg_hash, op_id_to_sig_map)
        })
        .next())
    }

    async fn add_outpoint(&self, outpoint: OutPoint) -> DbResult<bool> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let txid = DbTxid::from(outpoint.txid);
        let result = sqlx::query!(
            "INSERT OR IGNORE INTO selected_outpoints
                    (txid, vout) VALUES ($1, $2)",
            txid,
            outpoint.vout
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(result.rows_affected() > 0)
    }

    async fn selected_outpoints(&self) -> DbResult<HashSet<OutPoint>> {
        Ok(sqlx::query_as!(
            models::DbOutPoint,
            r#"SELECT
                txid AS "txid: DbTxid",
                vout AS "vout: DbInputIndex"
                FROM selected_outpoints"#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::from)?
        .into_iter()
        .map(|row| OutPoint {
            txid: *row.txid,
            vout: *row.vout,
        })
        .collect())
    }

    async fn add_kickoff_info(
        &self,
        deposit_txid: Txid,
        kickoff_info: KickoffInfo,
    ) -> DbResult<()> {
        let change_address = kickoff_info.change_address.address().to_string();
        let change_address_network = kickoff_info.change_address.network().to_string();

        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let deposit_txid = DbTxid::from(deposit_txid);
        let db_amount = DbAmount::from(kickoff_info.change_amt);
        sqlx::query!(
            "INSERT OR REPLACE INTO kickoff_info
                (txid, change_address, change_address_network, change_amount)
                VALUES ($1, $2, $3, $4)",
            deposit_txid,
            change_address,
            change_address_network,
            db_amount,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        for input in kickoff_info.funding_inputs {
            let input_txid = DbTxid::from(input.txid);
            sqlx::query!(
                "INSERT INTO funding_inputs
                    (kickoff_txid, input_txid, vout)
                    VALUES ($1, $2, $3)",
                deposit_txid,
                input_txid,
                input.vout
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        for utxo in kickoff_info.funding_utxos {
            let amount = DbAmount::from(utxo.value);
            let script_pubkey = DbScriptBuf::from(utxo.script_pubkey);
            sqlx::query!(
                "INSERT INTO funding_utxos
                    (kickoff_txid, value, script_pubkey)
                    VALUES ($1, $2, $3)",
                deposit_txid,
                amount,
                script_pubkey
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;
        }

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> DbResult<Option<KickoffInfo>> {
        // Query to retrieve KickoffInfo, funding inputs, and funding UTXOs in a single query
        let deposit_txid = DbTxid::from(deposit_txid);
        let rows = sqlx::query_as!(
            models::JoinedKickoffInfo,
            r#"
        SELECT
            ki.txid AS "ki_txid!: DbTxid",
            ki.change_address AS "ki_change_address!",
            ki.change_address_network AS "ki_change_address_network!",
            ki.change_amount AS "ki_change_amount!: DbAmount",
            fi.input_txid AS "fi_input_txid!: DbTxid",
            fi.vout AS "fi_vout!: DbInputIndex",
            fu.value AS "fu_value!: DbAmount",
            fu.script_pubkey AS "fu_script_pubkey!: DbScriptBuf"

            FROM kickoff_info ki
            LEFT JOIN funding_inputs fi ON fi.kickoff_txid = ki.txid
            LEFT JOIN funding_utxos fu ON fu.kickoff_txid = ki.txid
            WHERE ki.txid = $1
            "#,
            deposit_txid
        )
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
            .map(|row| {
                let vout = *row.fi_vout;
                let txid = *row.fi_input_txid;
                let value = *row.fu_value;
                let script_pubkey = row.fu_script_pubkey.deref().clone();

                (
                    TxOut {
                        value,
                        script_pubkey,
                    },
                    OutPoint { txid, vout },
                )
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
        let deposit_txid = DbTxid::from(deposit_txid);
        Ok(sqlx::query_as!(
            models::CheckPointIdx,
            r#"SELECT
                checkpoint_idx AS "value: u64"
                FROM strata_checkpoint
                WHERE txid = $1"#,
            deposit_txid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|v| v.value))
    }

    async fn set_checkpoint_index(
        &self,
        deposit_txid: Txid,
        checkpoint_index: u64,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        let deposit_txid = DbTxid::from(deposit_txid);
        let checkpoint_index = checkpoint_index as i64;
        sqlx::query!(
            "INSERT OR REPLACE INTO strata_checkpoint
                (txid, checkpoint_idx)
                VALUES ($1, $2)",
            deposit_txid,
            checkpoint_index,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }
}

#[async_trait]
impl DutyTrackerDb for SqliteDb {
    async fn get_last_fetched_duty_index(&self) -> DbResult<u64> {
        // Retrieve last fetched duty index from duty_index_tracker table
        let row =
            sqlx::query!("SELECT last_fetched_duty_index FROM duty_index_tracker WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(StorageError::from)?;

        Ok(row.map(|r| r.last_fetched_duty_index as u64).unwrap_or(0)) // Default to 0 if no record
    }

    async fn set_last_fetched_duty_index(&self, duty_index: u64) -> DbResult<()> {
        let duty_index = duty_index as i64;

        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_index_tracker (id, last_fetched_duty_index) VALUES (1, $1)",
            duty_index
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn fetch_duty_status(&self, duty_id: Txid) -> DbResult<Option<BridgeDutyStatus>> {
        let duty_id = DbTxid::from(duty_id);

        Ok(sqlx::query_as!(
            models::DutyTracker,
            r#"SELECT
                duty_id AS "duty_id!: DbTxid",
                status AS "status!: DbDutyStatus"
                FROM duty_tracker WHERE duty_id = $1"#,
            duty_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|r| r.status.deref().clone()))
    }

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) -> DbResult<()> {
        let duty_id = DbTxid::from(duty_id);
        let status = DbDutyStatus::from(status);

        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query!(
            "INSERT OR REPLACE INTO duty_tracker (duty_id, status) VALUES ($1, $2)",
            duty_id,
            status,
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }
}

#[async_trait]
impl BitcoinBlockTrackerDb for SqliteDb {
    async fn get_last_scanned_block_height(&self) -> DbResult<u64> {
        let row = sqlx::query!("SELECT block_height FROM bitcoin_block_index_tracker WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to fetch last scanned block height");

        Ok(row.map(|r| r.block_height as u64).unwrap_or(0)) // Default to 0 if no record
    }

    async fn set_last_scanned_block_height(&self, block_height: u64) -> DbResult<()> {
        let block_height = block_height as i64;

        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_block_index_tracker
                (id, block_height)
                VALUES (1, $1)",
            block_height
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_relevant_tx(&self, txid: &Txid) -> DbResult<Option<Transaction>> {
        let txid = DbTxid::from(*txid);

        Ok(sqlx::query_as!(
            models::RelevantTxIndex,
            r#"SELECT
                tx as "tx!: DbTransaction",
                txid as "txid!: DbTxid"
                FROM bitcoin_tx_index
                WHERE txid = $1"#,
            txid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .map(|row| row.tx.deref().clone()))
    }

    async fn add_relevant_tx(&self, tx: Transaction) -> DbResult<()> {
        let txid = DbTxid::from(tx.compute_txid());
        let tx = DbTransaction::from(tx);

        let mut sqlx_tx = self.pool.begin().await.map_err(StorageError::from)?;

        sqlx::query!(
            "INSERT OR REPLACE INTO bitcoin_tx_index
                (txid, tx)
                VALUES ($1, $2)",
            txid,
            tx
        )
        .execute(&mut *sqlx_tx)
        .await
        .map_err(StorageError::from)?;

        sqlx_tx.commit().await.map_err(StorageError::from)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arbitrary::{Arbitrary, Unstructured};
    use bitcoin::key::rand::{self, Rng};
    use secp256k1::rand::rngs::OsRng;
    use strata_bridge_primitives::{duties::WithdrawalStatus, params::prelude::NUM_ASSERT_DATA_TX};
    use strata_bridge_test_utils::prelude::*;

    use super::*;
    use crate::errors::DbError;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_public_db(pool: SqlitePool) {
        let operator_id: u32 = rand::thread_rng().gen();
        let deposit_txid = generate_txid();
        let db = SqliteDb::new(pool);

        let wots_public_keys = generate_wots_public_keys();
        assert!(
            db.get_wots_public_keys(operator_id, deposit_txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "wots public keys must not exist initially"
        );
        db.set_wots_public_keys(operator_id, deposit_txid, &wots_public_keys)
            .await
            .expect("must be able to set wots public keys");
        assert!(
            db.get_wots_public_keys(operator_id, deposit_txid)
                .await
                .is_ok_and(|v| v == Some(wots_public_keys)),
            "wots public keys must exist after setting"
        );

        let wots_signatures = generate_wots_signatures();
        assert!(
            db.get_wots_signatures(operator_id, deposit_txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "wots signatures must not exist initially"
        );
        db.set_wots_signatures(operator_id, deposit_txid, &wots_signatures)
            .await
            .expect("must be able to set wots signatures");
        assert!(
            db.get_wots_signatures(operator_id, deposit_txid)
                .await
                .is_ok_and(|v| v == Some(wots_signatures)),
            "wots signatures must exist after setting"
        );

        let signature = generate_signature();
        assert!(
            db.get_signature(operator_id, deposit_txid, 0)
                .await
                .is_ok_and(|v| v.is_none()),
            "signature must not exist initially"
        );
        db.set_signature(operator_id, deposit_txid, 0, signature)
            .await
            .expect("must be able to set signature");
        assert!(
            db.get_signature(operator_id, deposit_txid, 0)
                .await
                .is_ok_and(|v| v == Some(signature)),
            "signature must exist after setting"
        );

        let claim_txid = generate_txid();
        assert!(
            db.get_operator_and_deposit_for_claim(&claim_txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "claim txid must not exist initially"
        );
        db.register_claim_txid(claim_txid, operator_id, deposit_txid)
            .await
            .expect("must be able to register claim txid");
        assert!(
            db.get_operator_and_deposit_for_claim(&claim_txid)
                .await
                .is_ok_and(|v| v == Some((operator_id, deposit_txid))),
            "claim txid must exist after registering"
        );

        let pre_assert_txid = generate_txid();
        assert!(
            db.get_operator_and_deposit_for_pre_assert(&pre_assert_txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "pre assert txid must not exist initially"
        );
        db.register_pre_assert_txid(pre_assert_txid, operator_id, deposit_txid)
            .await
            .expect("must be able to register pre assert txid");
        assert!(
            db.get_operator_and_deposit_for_pre_assert(&pre_assert_txid)
                .await
                .is_ok_and(|v| v == Some((operator_id, deposit_txid))),
            "pre assert txid must exist after registering",
        );

        let assert_data_txids: [Txid; NUM_ASSERT_DATA_TX] =
            std::array::from_fn(|_| generate_txid());
        assert!(
            db.get_operator_and_deposit_for_assert_data(&assert_data_txids[0])
                .await
                .is_ok_and(|v| v.is_none()),
            "assert data txid must not exist initially"
        );
        db.register_assert_data_txids(assert_data_txids, operator_id, deposit_txid)
            .await
            .expect("must be able to register assert data txids");
        assert!(
            db.get_operator_and_deposit_for_assert_data(
                &assert_data_txids[rand::thread_rng().gen_range(0..NUM_ASSERT_DATA_TX)]
            )
            .await
            .is_ok_and(|v| v == Some((operator_id, deposit_txid))),
            "assert data txid must exist after registering"
        );

        let post_assert_txid = generate_txid();
        assert!(
            db.get_operator_and_deposit_for_post_assert(&post_assert_txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "post assert txid must not exist initially"
        );
        db.register_post_assert_txid(post_assert_txid, operator_id, deposit_txid)
            .await
            .expect("must be able to register post assert txid");
        assert!(
            db.get_operator_and_deposit_for_post_assert(&post_assert_txid)
                .await
                .is_ok_and(|v| v == Some((operator_id, deposit_txid))),
            "post assert txid must exist after registering"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_operator_db(pool: SqlitePool) {
        let outpoint = generate_outpoint();
        let pubnonce = generate_pubnonce();
        let secnonce = generate_secnonce();
        let message_sighash: [u8; 32] = rand::thread_rng().gen();
        let partial_signature = generate_partial_signature();
        let mut u = Unstructured::new(&[0; 1024]);
        let kickoff_info = KickoffInfo::arbitrary(&mut u).expect("must generate kickoff info");
        let txid = generate_txid();

        let db = SqliteDb::new(pool);

        assert!(
            db.collected_pubnonces(txid, 0)
                .await
                .is_ok_and(|v| v.is_empty()),
            "pubnonce must not exist initially"
        );
        db.add_pubnonce(txid, 0, 0, pubnonce.clone())
            .await
            .expect("must be able to add pubnonce");
        db.add_pubnonce(txid, 0, 1, pubnonce.clone())
            .await
            .expect("must be able to add pubnonce");
        assert!(
            db.collected_pubnonces(txid, 0)
                .await
                .is_ok_and(|v| v == BTreeMap::from([(0, pubnonce.clone()), (1, pubnonce.clone())])),
            "pubnonce must exist after adding"
        );

        assert!(
            db.get_secnonce(txid, 0).await.is_ok_and(|v| v.is_none()),
            "secnonce must not exist initially"
        );
        db.add_secnonce(txid, 0, secnonce.clone())
            .await
            .expect("must be able to add secnonce");
        assert!(
            db.get_secnonce(txid, 0)
                .await
                .is_ok_and(|v| v == Some(secnonce.clone())),
            "secnonce must exist after adding"
        );

        assert!(
            db.add_partial_signature(txid, 0, 0, partial_signature)
                .await
                .is_err_and(|e| matches!(e, DbError::Storage(StorageError::InvalidData(_)))),
            "must error if message hash is not present before adding partial sig"
        );

        assert!(
            db.collected_signatures_per_msg(txid, 0)
                .await
                .is_ok_and(|v| v.is_none()),
            "message hash and signature must not exist initially"
        );
        db.add_message_hash_and_signature(txid, 0, message_sighash.to_vec(), 0, partial_signature)
            .await
            .expect("must be able to add message hash and signature");
        assert!(
            db.collected_signatures_per_msg(txid, 0)
                .await
                .is_ok_and(|v| v
                    == Some((
                        message_sighash.to_vec(),
                        BTreeMap::from([(0, partial_signature)])
                    ))),
            "message hash and signature must exist after adding"
        );

        assert!(
            db.add_partial_signature(txid, 0, 0, partial_signature)
                .await
                .is_ok(),
            "must be able to add partial signature if message hash is present"
        );

        assert!(
            db.selected_outpoints().await.is_ok_and(|v| v.is_empty()),
            "outpoint must not exist initially"
        );
        assert!(
            db.add_outpoint(outpoint).await.is_ok_and(|v| v),
            "must be able to add outpoint"
        );
        assert!(
            db.selected_outpoints()
                .await
                .is_ok_and(|v| v == std::iter::once(outpoint).collect::<HashSet<OutPoint>>()),
            "outpoint must exist after adding"
        );

        assert!(
            db.get_kickoff_info(txid).await.is_ok_and(|v| v.is_none()),
            "kickoff info must not exist initially"
        );
        db.add_kickoff_info(txid, kickoff_info.clone())
            .await
            .expect("must be able to add kickoff info");
        assert!(
            db.get_kickoff_info(txid)
                .await
                .is_ok_and(|v| v == Some(kickoff_info.clone())),
            "kickoff info must exist after adding"
        );

        assert!(
            db.get_checkpoint_index(txid)
                .await
                .is_ok_and(|v| v.is_none()),
            "checkpoint index must not exist initially"
        );
        db.set_checkpoint_index(txid, 0)
            .await
            .expect("must be able to set checkpoint index");
        assert!(
            db.get_checkpoint_index(txid)
                .await
                .is_ok_and(|v| v == Some(0)),
            "checkpoint index must exist after setting"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_duty_tracker_db(pool: SqlitePool) {
        let db = SqliteDb::new(pool);

        let duty_id = generate_txid();
        let block_height: u64 = rand::thread_rng().gen();

        let withdrawal_fulfillment_txid = generate_txid();
        let claim_txid = generate_txid();
        let superblock_start_ts = OsRng.gen();
        // This might change later after [STR-821](https://alpenlabs.atlassian.net/browse/STR-754).
        // So, hardcoding the value for now.
        let bridge_duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Claim {
            withdrawal_fulfillment_txid,
            superblock_start_ts,
            claim_txid,
        });

        assert!(
            db.fetch_duty_status(duty_id)
                .await
                .is_ok_and(|v| v.is_none()),
            "duty status must not exist initially"
        );
        db.update_duty_status(duty_id, bridge_duty_status.clone())
            .await
            .expect("must be able to update duty status");
        assert!(
            db.fetch_duty_status(duty_id)
                .await
                .is_ok_and(|v| v == Some(bridge_duty_status)),
            "duty status must exist after updating"
        );

        let new_bridge_duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Kickoff {
            withdrawal_fulfillment_txid: generate_txid(),
            kickoff_txid: generate_txid(),
        });
        assert!(
            db.update_duty_status(duty_id, new_bridge_duty_status.clone())
                .await
                .is_ok(),
            "should be able to update duty status"
        );
        assert!(
            db.fetch_duty_status(duty_id)
                .await
                .is_ok_and(|v| v == Some(new_bridge_duty_status)),
            "duty status must change after updating"
        );

        assert!(
            db.get_last_fetched_duty_index().await.is_ok_and(|v| v == 0),
            "last fetched duty index must not exist initially"
        );
        db.set_last_fetched_duty_index(block_height)
            .await
            .expect("must be able to set last fetched duty index");
        assert!(
            db.get_last_fetched_duty_index()
                .await
                .is_ok_and(|v| v == block_height),
            "last fetched duty index must exist after setting"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    fn test_bitcoin_block_tracker_db(pool: SqlitePool) {
        let db = SqliteDb::new(pool);

        let tx = generate_tx(2, 1);
        let block_height: u64 = OsRng.gen();

        assert!(
            db.get_last_scanned_block_height()
                .await
                .is_ok_and(|v| v == 0),
            "last scanned block height must not exist initially"
        );
        db.set_last_scanned_block_height(block_height)
            .await
            .expect("must be able to set last scanned block height");
        assert!(
            db.get_last_scanned_block_height()
                .await
                .is_ok_and(|v| v == block_height),
            "last scanned block height must exist after setting"
        );

        assert!(
            db.get_relevant_tx(&tx.compute_txid())
                .await
                .is_ok_and(|v| v.is_none()),
            "relevant tx must not exist initially"
        );
        db.add_relevant_tx(tx.clone())
            .await
            .expect("must be able to add relevant tx");
        assert!(
            db.get_relevant_tx(&tx.compute_txid())
                .await
                .is_ok_and(|v| v == Some(tx)),
            "relevant tx must exist after adding"
        );
    }
}
