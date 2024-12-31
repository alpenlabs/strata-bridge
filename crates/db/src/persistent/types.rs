use std::{ops::Deref, str::FromStr};

use bitcoin::{consensus, Txid};
use rkyv::rancor::Error as RkyvError;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteValueRef, Sqlite};
use strata_bridge_primitives::{duties::BridgeDutyStatus, scripts::wots, types::OperatorIdx};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct DbOperatorId(OperatorIdx);

impl Deref for DbOperatorId {
    type Target = OperatorIdx;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<OperatorIdx> for DbOperatorId {
    fn from(value: OperatorIdx) -> Self {
        Self(value)
    }
}

impl From<i64> for DbOperatorId {
    fn from(value: i64) -> Self {
        Self(value as u32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbTxid(Txid);

impl Deref for DbTxid {
    type Target = Txid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Txid> for DbTxid {
    fn from(value: Txid) -> Self {
        Self(value)
    }
}

// Implement Type for DbTxid to map it to SQLite's TEXT
impl sqlx::Type<Sqlite> for DbTxid {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbTxid {
    fn decode(
        value: <Sqlite as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let txid_hex: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let txid = consensus::encode::deserialize_hex(&txid_hex)
            .map_err(|_| sqlx::Error::Decode("Failed to decode Txid".into()))?;

        Ok(DbTxid(txid))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbTxid {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let txid_hex = consensus::encode::serialize_hex(&self.0);

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&txid_hex, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DbWotsPublicKeys(wots::PublicKeys);

impl Deref for DbWotsPublicKeys {
    type Target = wots::PublicKeys;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<wots::PublicKeys> for DbWotsPublicKeys {
    fn from(value: wots::PublicKeys) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbWotsPublicKeys {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbWotsPublicKeys {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes: Vec<u8> = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let keys = rkyv::from_bytes::<wots::PublicKeys, RkyvError>(&bytes)
            .map_err(|_| sqlx::Error::Decode("Failed to decode PublicKeys".into()))?;

        Ok(DbWotsPublicKeys(keys))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbWotsPublicKeys {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'q>>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let bytes = rkyv::to_bytes::<RkyvError>(&self.0)
            .map_err(|_| sqlx::Error::Decode("Failed to serialize wots public keys".into()))?
            .to_vec();

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&bytes, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DbWotsSignatures(wots::Signatures);

impl Deref for DbWotsSignatures {
    type Target = wots::Signatures;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<wots::Signatures> for DbWotsSignatures {
    fn from(value: wots::Signatures) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbWotsSignatures {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbWotsSignatures {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes: Vec<u8> = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let signatures = rkyv::from_bytes::<wots::Signatures, RkyvError>(&bytes)
            .map_err(|_| sqlx::Error::Decode("Failed to decode PublicKeys".into()))?;

        Ok(DbWotsSignatures(signatures))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbWotsSignatures {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'q>>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let bytes = rkyv::to_bytes::<RkyvError>(&self.0)
            .map_err(|_| sqlx::Error::Decode("Failed to serialize wots public keys".into()))?
            .to_vec();

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&bytes, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbSignature(Signature);

impl Deref for DbSignature {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Signature> for DbSignature {
    fn from(value: Signature) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbSignature {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbSignature {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let signature_str: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let signature = Signature::from_str(&signature_str)
            .map_err(|_| sqlx::Error::Decode("Failed to decode schnorr::Signature".into()))?;
        Ok(DbSignature(signature))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbSignature {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let signature_str = self.0.to_string();
        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&signature_str, buf)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbDutyStatus(BridgeDutyStatus);

impl Deref for DbDutyStatus {
    type Target = BridgeDutyStatus;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbDutyStatus {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let status_json: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let status = serde_json::from_str(&status_json)
            .map_err(|_| sqlx::Error::Decode("Failed to decode BridgeDutyStatus".into()))?;
        Ok(DbDutyStatus(status))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbDutyStatus {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let status_json = serde_json::to_string(&self.0)
            .map_err(|_| sqlx::Error::Encode("Failed to serialize BridgeDutyStatus".into()))?;
        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&status_json, buf)
    }
}
