//! SQLite implementation of the persistent storage layer.

use std::{collections::BTreeMap, ops::Deref};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use musig2::{AggNonce, PartialSignature, PubNonce};
use secp256k1::schnorr::Signature;
use sqlx::SqlitePool;
use strata_bridge_primitives::{
    constants::NUM_ASSERT_DATA_TX, scripts::taproot::TaprootWitness, types::OperatorIdx, wots,
};
use strata_bridge_stake_chain::transactions::stake::StakeTxData;
use tracing::{error, warn};

use super::{
    config::DbConfig,
    errors::StorageError,
    models::DbStakeTxData,
    types::{
        DbAggNonce, DbHash, DbInputIndex, DbPartialSig, DbSignature, DbTaprootWitness, DbTxid,
        DbWots256PublicKey, DbWotsPublicKeys, DbWotsSignatures, DbXOnlyPublicKey,
    },
};
use crate::{
    errors::{DbError, DbResult},
    operator::OperatorDb,
    persistent::{models, types::DbPubNonce},
    public::PublicDb,
};

/// A SQLite database connection pool.
#[derive(Debug, Clone)]
pub struct SqliteDb {
    /// The database connection pool.
    pool: SqlitePool,

    /// The database configuration.
    config: DbConfig,
}

impl SqliteDb {
    /// Creates a new instance of the SQLite database connection pool with default config.
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            config: DbConfig::default(),
        }
    }

    /// Creates a new instance of the SQLite database connection pool with the given config.
    pub const fn new_with_config(pool: SqlitePool, config: DbConfig) -> Self {
        Self { pool, config }
    }

    /// Returns a reference to the database configuration.
    pub const fn config(&self) -> &DbConfig {
        &self.config
    }

    /// Returns the underlying [`SqlitePool`].
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl PublicDb for SqliteDb {
    async fn get_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::PublicKeys>> {
        execute_with_retries(self.config(), || async {
            let deposit_txid = DbTxid::from(deposit_txid);
            let result = sqlx::query_as!(
                models::WotsPublicKey,
                r#"SELECT
                    public_keys as "public_keys: DbWotsPublicKeys",
                    operator_idx,
                    deposit_txid AS "deposit_txid: DbTxid"
                    FROM wots_public_keys
                    WHERE operator_idx = $1 AND deposit_txid = $2"#,
                operator_idx,
                deposit_txid,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|v| v.public_keys.deref().clone());

            Ok(result)
        })
        .await
    }

    async fn set_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
            let deposit_txid = DbTxid::from(deposit_txid);
            let public_keys = DbWotsPublicKeys::from(public_keys.clone());

            sqlx::query!(
                "INSERT OR REPLACE INTO wots_public_keys
                    (operator_idx, deposit_txid, public_keys)
                    VALUES ($1, $2, $3)",
                operator_idx,
                deposit_txid,
                public_keys,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;

            Ok(())
        })
        .await
    }

    async fn get_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::Signatures>> {
        execute_with_retries(self.config(), || async move {
            let deposit_txid = DbTxid::from(deposit_txid);
            let result = sqlx::query_as!(
                models::WotsSignature,
                r#"SELECT signatures AS "signatures: DbWotsSignatures",
                    operator_idx,
                    deposit_txid AS "deposit_txid: DbTxid"
                    FROM wots_signatures
                    WHERE operator_idx = $1 AND deposit_txid = $2"#,
                operator_idx,
                deposit_txid,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|v| v.signatures.deref().clone());

            Ok(result)
        })
        .await
    }

    async fn set_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let deposit_txid = DbTxid::from(deposit_txid);
            let db_signatures = DbWotsSignatures::from(signatures.clone());
            sqlx::query!(
                "INSERT OR REPLACE INTO wots_signatures
                    (operator_idx, deposit_txid, signatures)
                    VALUES ($1, $2, $3)",
                operator_idx,
                deposit_txid,
                db_signatures,
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;
            Ok(())
        })
        .await
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<Signature>> {
        execute_with_retries(self.config(), || async move {
            let txid = DbTxid::from(txid);
            let result = sqlx::query_as!(
                models::Signature,
                r#"SELECT
                    signature AS "signature: DbSignature",
                    operator_idx,
                    txid AS "txid: DbTxid",
                    input_index
                    FROM signatures
                    WHERE operator_idx = $1 AND txid = $2 AND input_index = $3"#,
                operator_idx,
                txid,
                input_index,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|v| *v.signature);

            Ok(result)
        })
        .await
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let signature = DbSignature::from(signature);
            let txid = DbTxid::from(txid);
            sqlx::query!(
                "INSERT OR REPLACE INTO signatures
                    (signature, operator_idx, txid, input_index)
                    VALUES ($1, $2, $3, $4)",
                signature,
                operator_idx,
                txid,
                input_index
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;

            Ok(())
        })
        .await
    }

    async fn add_deposit_txid(&self, deposit_txid: Txid) -> DbResult<()> {
        execute_with_retries(&self.config, || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let new_index = sqlx::query!("SELECT COUNT(*) AS cnt FROM deposits")
                .fetch_one(&mut *tx)
                .await
                .map_err(StorageError::from)?
                .cnt;

            let deposit_txid = DbTxid::from(deposit_txid);
            sqlx::query!(
                "INSERT OR IGNORE INTO deposits (deposit_txid, deposit_id) VALUES ($1, $2)",
                deposit_txid,
                new_index
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;

            Ok(())
        })
        .await
    }

    async fn get_deposit_id(&self, deposit_txid: Txid) -> DbResult<Option<u32>> {
        execute_with_retries(self.config(), || async {
            let deposit_txid = DbTxid::from(deposit_txid);
            Ok(sqlx::query!(
                r#"SELECT deposit_id AS "deposit_id: u32" FROM deposits WHERE deposit_txid = $1"#,
                deposit_txid
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| row.deposit_id))
        })
        .await
    }

    async fn add_stake_txid(&self, operator_idx: OperatorIdx, stake_txid: Txid) -> DbResult<()> {
        execute_with_retries(&self.config, || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let stake_id = sqlx::query!(
                "SELECT COUNT(*) AS cnt FROM operator_stake_txids WHERE operator_idx = $1",
                operator_idx
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(StorageError::from)?
            .first()
            .map(|row| row.cnt)
            .unwrap_or(0);

            let stake_txid = DbTxid::from(stake_txid);
            sqlx::query!(
                "INSERT OR IGNORE INTO operator_stake_txids
                        (operator_idx, stake_id, stake_txid)
                        VALUES ($1, $2, $3)",
                operator_idx,
                stake_id,
                stake_txid
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;

            Ok(())
        })
        .await
    }

    async fn get_stake_txid(
        &self,
        operator_idx: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<Txid>> {
        execute_with_retries(self.config(), || async {
            Ok(sqlx::query!(
                r#"SELECT stake_txid AS "stake_txid: DbTxid"
                    FROM operator_stake_txids
                    WHERE operator_idx = $1 AND stake_id = $2"#,
                operator_idx,
                stake_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| *row.stake_txid))
        })
        .await
    }

    async fn set_pre_stake(&self, operator_idx: OperatorIdx, pre_stake: OutPoint) -> DbResult<()> {
        execute_with_retries(&self.config, || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let pre_stake_txid = DbTxid::from(pre_stake.txid);
            let pre_stake_vout = DbInputIndex::from(pre_stake.vout);

            sqlx::query!(
                "INSERT OR IGNORE INTO operator_pre_stake_data
                    (operator_idx, pre_stake_txid, pre_stake_vout)
                    VALUES ($1, $2, $3)",
                operator_idx,
                pre_stake_txid,
                pre_stake_vout
            )
            .execute(&mut *tx)
            .await
            .map_err(StorageError::from)?;

            tx.commit().await.map_err(StorageError::from)?;

            Ok(())
        })
        .await
    }

    async fn get_pre_stake(&self, operator_idx: OperatorIdx) -> DbResult<Option<OutPoint>> {
        execute_with_retries(self.config(), || async {
            Ok(sqlx::query!(
                r#"SELECT pre_stake_txid AS "txid: DbTxid", pre_stake_vout AS "vout: DbInputIndex"
                    FROM operator_pre_stake_data
                    WHERE operator_idx = $1"#,
                operator_idx
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| OutPoint {
                txid: *row.txid,
                vout: *row.vout,
            }))
        })
        .await
    }

    async fn add_stake_data(
        &self,
        operator_idx: OperatorIdx,
        stake_index: u32,
        stake_data: StakeTxData,
    ) -> DbResult<()> {
        execute_with_retries(&self.config, || {
            let pool = self.pool.to_owned();
            let stake_data = stake_data.to_owned();
            async move {
                let mut tx = pool.begin().await.map_err(StorageError::from)?;
                let stake_data = DbStakeTxData::new(stake_index, stake_data);

                sqlx::query!(
                    "INSERT OR IGNORE INTO operator_stake_data
                        (operator_idx, deposit_idx, funding_txid, funding_vout, hash, operator_pubkey, withdrawal_fulfillment_pk)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    operator_idx,
                    stake_index,
                    stake_data.funding_txid,
                    stake_data.funding_vout,
                    stake_data.hash,
                    stake_data.operator_pubkey,
                    stake_data.withdrawal_fulfillment_pk,
                )
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;

                tx.commit().await.map_err(StorageError::from)?;

                Ok(())
            }
        }).await
    }

    async fn get_stake_data(
        &self,
        operator_idx: OperatorIdx,
        deposit_id: u32,
    ) -> DbResult<Option<StakeTxData>> {
        execute_with_retries(self.config(), || async {
            Ok(sqlx::query_as!(
                models::DbStakeTxData,
                r#"SELECT
                    deposit_idx AS "deposit_idx: u32",
                    funding_txid AS "funding_txid: DbTxid",
                    funding_vout AS "funding_vout: DbInputIndex",
                    hash AS "hash: DbHash",
                    operator_pubkey AS "operator_pubkey: DbXOnlyPublicKey",
                    withdrawal_fulfillment_pk AS "withdrawal_fulfillment_pk: DbWots256PublicKey"
                    FROM operator_stake_data
                    WHERE operator_idx = $1 AND deposit_idx = $2"#,
                operator_idx,
                deposit_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| DbStakeTxData { ..row }.into()))
        })
        .await
    }

    async fn add_all_stake_data(&self, data: Vec<(OperatorIdx, u32, StakeTxData)>) -> DbResult<()> {
        execute_with_retries(&self.config, || {
            let pool = self.pool.to_owned();
            let data = data.clone();
            async move {
                let mut tx = pool.begin().await.map_err(StorageError::from)?;

                for (operator_idx, deposit_idx, stake_data) in data {
                    let stake_data = DbStakeTxData::new(deposit_idx, stake_data);
                    sqlx::query!(
                        "INSERT OR IGNORE INTO operator_stake_data
                            (operator_idx, deposit_idx, funding_txid, funding_vout, hash, operator_pubkey, withdrawal_fulfillment_pk)
                            VALUES ($1, $2, $3, $4, $5, $6, $7)",
                        operator_idx,
                        deposit_idx,
                        stake_data.funding_txid,
                        stake_data.funding_vout,
                        stake_data.hash,
                        stake_data.operator_pubkey,
                        stake_data.withdrawal_fulfillment_pk,
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(StorageError::from)?;
                }

                tx.commit().await.map_err(StorageError::from)?;

                Ok(())
            }
        }).await
    }

    async fn get_all_stake_data(
        &self,
        operator_idx: OperatorIdx,
    ) -> DbResult<BTreeMap<u32, StakeTxData>> {
        execute_with_retries(self.config(), || async {
            Ok(sqlx::query_as!(
                models::DbStakeTxData,
                r#"SELECT
                    deposit_idx AS "deposit_idx: u32",
                    funding_txid AS "funding_txid: DbTxid",
                    funding_vout AS "funding_vout: DbInputIndex",
                    hash AS "hash: DbHash",
                    withdrawal_fulfillment_pk AS "withdrawal_fulfillment_pk: DbWots256PublicKey",
                    operator_pubkey AS "operator_pubkey: DbXOnlyPublicKey"
                    FROM operator_stake_data
                    WHERE operator_idx = $1
                    ORDER BY deposit_idx ASC"#,
                operator_idx,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::from)?
            .into_iter()
            .map(|row| (row.deposit_idx, DbStakeTxData { ..row }.into()))
            .collect())
        })
        .await
    }

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let claim_txid = DbTxid::from(claim_txid);
            let deposit_txid = DbTxid::from(deposit_txid);
            sqlx::query!(
                "INSERT OR REPLACE INTO claim_txid_to_operator_index_and_deposit_txid
                    (claim_txid, operator_idx, deposit_txid)
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
        })
        .await
    }

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        execute_with_retries(self.config(), || async {
            let claim_txid = DbTxid::from(*claim_txid);
            Ok(sqlx::query_as!(
                models::ClaimToOperatorAndDeposit,
                r#"SELECT
                    operator_idx,
                    deposit_txid AS "deposit_txid!: DbTxid",
                    claim_txid AS "claim_txid!: DbTxid"
                    FROM claim_txid_to_operator_index_and_deposit_txid
                    WHERE claim_txid = $1"#,
                claim_txid,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| (*row.operator_idx, *row.deposit_txid)))
        })
        .await
    }

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let post_assert_txid = DbTxid::from(post_assert_txid);
            let deposit_txid = DbTxid::from(deposit_txid);
            sqlx::query!(
                "INSERT OR REPLACE INTO post_assert_txid_to_operator_index_and_deposit_txid
                (post_assert_txid, operator_idx, deposit_txid)
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
        })
        .await
    }

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        execute_with_retries(self.config(), || async {
            let post_assert_txid = DbTxid::from(*post_assert_txid);
            Ok(sqlx::query_as!(
                models::PostAssertToOperatorAndDeposit,
                r#"SELECT
                    post_assert_txid AS "post_assert_txid!: DbTxid",
                    operator_idx,
                    deposit_txid AS "deposit_txid!: DbTxid"
                    FROM post_assert_txid_to_operator_index_and_deposit_txid
                    WHERE post_assert_txid = $1"#,
                post_assert_txid
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| (*row.operator_idx, *row.deposit_txid)))
        })
        .await
    }

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let deposit_txid = DbTxid::from(deposit_txid);
            for txid in assert_data_txids {
                let assert_data_txid = DbTxid::from(txid);
                sqlx::query!(
                    "INSERT OR REPLACE INTO assert_data_txid_to_operator_and_deposit
                        (assert_data_txid, operator_idx, deposit_txid)
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
        })
        .await
    }

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        execute_with_retries(self.config(), || async {
            let assert_data_txid = DbTxid::from(*assert_data_txid);
            Ok(sqlx::query_as!(
                models::AssertDataToOperatorAndDeposit,
                r#"SELECT
                    assert_data_txid AS "assert_data_txid!: DbTxid",
                    operator_idx,
                    deposit_txid AS "deposit_txid!: DbTxid"
                    FROM assert_data_txid_to_operator_and_deposit
                    WHERE assert_data_txid = ?"#,
                assert_data_txid,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|record| (*record.operator_idx, *record.deposit_txid)))
        })
        .await
    }

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || async {
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let pre_assert_data_txid = DbTxid::from(pre_assert_data_txid);
            let deposit_txid = DbTxid::from(deposit_txid);
            sqlx::query!(
                "INSERT OR REPLACE INTO pre_assert_txid_to_operator_and_deposit
                    (pre_assert_data_txid, operator_idx, deposit_txid)
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
        })
        .await
    }

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        execute_with_retries(self.config(), || async {
            let pre_assert_data_txid = DbTxid::from(*pre_assert_data_txid);
            Ok(sqlx::query_as!(
                models::PreAssertToOperatorAndDeposit,
                r#"SELECT
                    pre_assert_data_txid AS "pre_assert_txid!: DbTxid",
                    operator_idx,
                    deposit_txid AS "deposit_txid!: DbTxid"
                    FROM pre_assert_txid_to_operator_and_deposit
                    WHERE pre_assert_data_txid = $1"#,
                pre_assert_data_txid,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|record| (*record.operator_idx, *record.deposit_txid)))
        })
        .await
    }
}

#[async_trait]
impl OperatorDb for SqliteDb {
    async fn get_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PubNonce>> {
        execute_with_retries(self.config(), || async {
            let txid = DbTxid::from(txid);
            Ok(sqlx::query_as!(
                models::PubNonces,
                r#"SELECT
                    operator_idx,
                    pubnonce AS "pubnonce: DbPubNonce",
                    txid AS "txid: DbTxid",
                    input_index AS "input_index: DbInputIndex"
                    FROM pub_nonces
                    WHERE operator_idx = $1 AND txid = $2 AND input_index = $3"#,
                operator_idx,
                txid,
                input_index
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| row.pubnonce.deref().clone()))
        })
        .await
    }

    async fn set_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        pub_nonce: PubNonce,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || {
            let pub_nonce = pub_nonce.to_owned();

            async move {
                let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

                let txid = DbTxid::from(txid);
                let pubnonce = DbPubNonce::from(pub_nonce);
                sqlx::query!(
                    "INSERT OR REPLACE INTO pub_nonces
                        (operator_idx, txid, input_index, pubnonce)
                        VALUES ($1, $2, $3, $4)",
                    operator_idx,
                    txid,
                    input_index,
                    pubnonce,
                )
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;

                tx.commit().await.map_err(StorageError::from)?;

                Ok(())
            }
        })
        .await
    }

    async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<AggNonce>> {
        execute_with_retries(self.config(), || async {
            let txid = DbTxid::from(txid);
            Ok(sqlx::query_as!(
                models::AggregatedNonces,
                r#"SELECT
                    agg_nonce AS "agg_nonce: DbAggNonce",
                    txid AS "txid: DbTxid",
                    input_index AS "input_index: DbInputIndex"
                    FROM aggregated_nonces
                    WHERE txid = $1 AND input_index = $2"#,
                txid,
                input_index
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| row.agg_nonce.deref().clone()))
        })
        .await
    }

    async fn set_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
        agg_nonce: AggNonce,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || {
            let agg_nonce = agg_nonce.to_owned();

            async move {
                let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

                let txid = DbTxid::from(txid);
                let agg_nonce = DbAggNonce::from(agg_nonce);
                sqlx::query!(
                    "INSERT OR REPLACE INTO aggregated_nonces
                        (txid, input_index, agg_nonce)
                        VALUES ($1, $2, $3)",
                    txid,
                    input_index,
                    agg_nonce,
                )
                .execute(&mut *tx)
                .await
                .map_err(StorageError::from)?;

                tx.commit().await.map_err(StorageError::from)?;

                Ok(())
            }
        })
        .await
    }

    async fn get_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PartialSignature>> {
        execute_with_retries(self.config(), || async {
            let txid = DbTxid::from(txid);
            Ok(sqlx::query_as!(
                models::PartialSignatures,
                r#"SELECT
                    operator_idx,
                    partial_signature AS "partial_signature: DbPartialSig",
                    txid AS "txid: DbTxid",
                    input_index AS "input_index: DbInputIndex"
                    FROM partial_signatures
                    WHERE operator_idx = $1 AND txid = $2 AND input_index = $3"#,
                operator_idx,
                txid,
                input_index
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| *row.partial_signature))
        })
        .await
    }

    async fn set_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: PartialSignature,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || {
            let signature = signature.to_owned();

            async move {
                let txid = DbTxid::from(txid);
                let partial_signature = DbPartialSig::from(signature);

                sqlx::query!(
                    "INSERT OR REPLACE INTO partial_signatures
                        (operator_idx, txid, input_index, partial_signature)
                        VALUES ($1, $2, $3, $4)",
                    operator_idx,
                    txid,
                    input_index,
                    partial_signature,
                )
                .execute(&self.pool)
                .await
                .map_err(StorageError::from)?;

                Ok(())
            }
        })
        .await
    }

    async fn get_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<TaprootWitness>> {
        execute_with_retries(self.config(), || async {
            let txid = DbTxid::from(txid);
            Ok(sqlx::query_as!(
                models::Witnesses,
                r#"SELECT
                    operator_idx,
                    witness AS "witness: DbTaprootWitness",
                    txid AS "txid: DbTxid",
                    input_index AS "input_index: DbInputIndex"
                    FROM witnesses
                    WHERE operator_idx = $1 AND txid = $2 AND input_index = $3"#,
                operator_idx,
                txid,
                input_index
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(StorageError::from)?
            .map(|row| row.witness.deref().clone()))
        })
        .await
    }

    async fn set_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        witness: TaprootWitness,
    ) -> DbResult<()> {
        execute_with_retries(self.config(), || {
            let witness = witness.to_owned();

            async move {
                let txid = DbTxid::from(txid);
                let witness = DbTaprootWitness::from(witness);

                sqlx::query!(
                    "INSERT OR REPLACE INTO witnesses
                        (operator_idx, txid, input_index, witness)
                        VALUES ($1, $2, $3, $4)",
                    operator_idx,
                    txid,
                    input_index,
                    witness,
                )
                .execute(&self.pool)
                .await
                .map_err(StorageError::from)?;

                Ok(())
            }
        })
        .await
    }
}

/// Executes an operation for a given number of retries with a backoff period before erroring out.
///
/// This is useful for retrying transactions that may fail when another thread is holding the lock.
pub async fn execute_with_retries<F, Fut, Res>(
    config: &DbConfig,
    mut operation: F,
) -> Result<Res, DbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = DbResult<Res>>,
    Res: Sized,
{
    let mut retries = 0;
    loop {
        match operation().await {
            Ok(res) => return Ok(res),
            Err(err) if retries < config.max_retry_count() => {
                warn!(msg = "operation failed, retrying", %err, %retries);
                retries += 1;
                tokio::time::sleep(config.backoff_period()).await;
            }
            Err(err) => {
                error!(msg = "operation failed after retries", %err, %retries);
                return Err(err)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::{self, Hash},
        key::rand::{self, Rng},
    };
    use secp256k1::rand::rngs::OsRng;
    use strata_bridge_test_utils::prelude::*;

    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_public_db(pool: SqlitePool) {
        let operator_id: u32 = rand::thread_rng().gen();
        let deposit_txid = generate_txid();
        let db = SqliteDb::new_with_config(pool, DbConfig::default());

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
    async fn test_deposits_table(pool: SqlitePool) {
        let db = SqliteDb::new(pool);

        let num_deposits = OsRng.gen_range(3..20);
        for i in 0..num_deposits {
            let deposit_txid = generate_txid();
            assert!(db
                .get_deposit_id(deposit_txid)
                .await
                .is_ok_and(|v| v.is_none()));
            db.add_deposit_txid(deposit_txid)
                .await
                .expect("must be able to add deposit id");
            assert!(
                db.get_deposit_id(deposit_txid)
                    .await
                    .is_ok_and(|v| v == Some(i)),
                "deposit id must exist after adding and must increment"
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_repeated_deposits(pool: SqlitePool) {
        let db = SqliteDb::new(pool);

        let deposit_txid = generate_txid();
        assert!(db
            .get_deposit_id(deposit_txid)
            .await
            .is_ok_and(|v| v.is_none()));

        for _ in 0..3 {
            db.add_deposit_txid(deposit_txid)
                .await
                .expect("must be able to add deposit id");
            assert!(
                db.get_deposit_id(deposit_txid)
                    .await
                    .is_ok_and(|v| v == Some(0)),
                "deposit id must exist after adding and must _not_ increment"
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_stake_db(pool: SqlitePool) {
        let db = SqliteDb::new(pool);

        let operator_id = OsRng.gen();
        let pre_stake = OutPoint {
            txid: generate_txid(),
            vout: OsRng.gen_range(0..10),
        };
        assert!(
            db.get_pre_stake(operator_id)
                .await
                .is_ok_and(|v| v.is_none()),
            "pre stake must not exist initially"
        );
        db.set_pre_stake(operator_id, pre_stake)
            .await
            .expect("must be able to set pre stake");
        assert!(
            db.get_pre_stake(operator_id)
                .await
                .is_ok_and(|v| v == Some(pre_stake)),
            "pre stake must exist after setting"
        );

        let num_stake = OsRng.gen_range(3..10);
        let withdrawal_fulfillment_pk = generate_wots_public_keys().withdrawal_fulfillment;

        let operator_id: u32 = rand::thread_rng().gen();
        for stake_id in 0..num_stake {
            let stake_txid = generate_txid();
            let stake_hash = hashes::sha256::Hash::from_slice(&OsRng.gen::<[u8; 32]>()).unwrap();
            assert!(
                db.get_stake_txid(operator_id, stake_id)
                    .await
                    .is_ok_and(|v| v.is_none()),
                "stake id must not be set initially"
            );
            db.add_stake_txid(operator_id, stake_txid)
                .await
                .expect("must be able to set stake txid");
            assert!(
                db.get_stake_txid(operator_id, stake_id)
                    .await
                    .is_ok_and(|v| v == Some(stake_txid)),
                "stake txid must exist after setting and stake_id must increment but got: {:?}",
                db.get_stake_txid(operator_id, stake_id).await
            );

            let stake_data = StakeTxData {
                operator_funds: OutPoint {
                    txid: generate_txid(),
                    vout: OsRng.gen_range(0..10),
                },
                hash: stake_hash,
                withdrawal_fulfillment_pk: withdrawal_fulfillment_pk.clone(),
                operator_pubkey: generate_xonly_pubkey(),
            };

            assert!(
                db.get_stake_data(operator_id, stake_id)
                    .await
                    .is_ok_and(|v| v.is_none()),
                "stake data must not exist initially"
            );
            db.add_stake_data(operator_id, stake_id, stake_data.to_owned())
                .await
                .expect("must be able to set stake data");
            assert!(
                db.get_stake_data(operator_id, stake_id)
                    .await
                    .is_ok_and(|v| v == Some(stake_data.to_owned())),
                "stake data must exist after setting and stake_id must increment"
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_operator_db(pool: SqlitePool) {
        let pubnonce = generate_pubnonce();
        let agg_nonce = generate_agg_nonce();
        let partial_signature = generate_partial_signature();
        let txid = generate_txid();
        let operator_idx = 0;
        let input_index = 0;

        let db = SqliteDb::new(pool);

        // Test pub nonce
        assert!(
            db.get_pub_nonce(operator_idx, txid, input_index)
                .await
                .is_ok_and(|v| v.is_none()),
            "pub nonce must not exist initially"
        );
        db.set_pub_nonce(operator_idx, txid, input_index, pubnonce.clone())
            .await
            .expect("must be able to set pub nonce");
        assert!(
            db.get_pub_nonce(operator_idx, txid, input_index)
                .await
                .is_ok_and(|v| v == Some(pubnonce.clone())),
            "pub nonce must exist after setting"
        );

        // Test aggregated nonce
        assert!(
            db.get_aggregated_nonce(txid, input_index)
                .await
                .is_ok_and(|v| v.is_none()),
            "aggregated nonce must not exist initially"
        );
        db.set_aggregated_nonce(txid, input_index, agg_nonce.clone())
            .await
            .expect("must be able to set aggregated nonce");
        assert!(
            db.get_aggregated_nonce(txid, input_index)
                .await
                .is_ok_and(|v| v == Some(agg_nonce.clone())),
            "aggregated nonce must exist after setting"
        );

        // Test partial signature
        assert!(
            db.get_partial_signature(operator_idx, txid, input_index)
                .await
                .is_ok_and(|v| v.is_none()),
            "partial signature must not exist initially"
        );
        db.set_partial_signature(operator_idx, txid, input_index, partial_signature)
            .await
            .expect("must be able to set partial signature");
        assert!(
            db.get_partial_signature(operator_idx, txid, input_index)
                .await
                .is_ok_and(|v| v == Some(partial_signature)),
            "partial signature must exist after setting"
        );
    }
}
