use std::{ops::Deref, str::FromStr};

use bitcoin::{consensus, hex::DisplayHex, Amount, ScriptBuf, Txid};
use musig2::{BinaryEncoding, PartialSignature, PubNonce, SecNonce};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct DbInputIndex(u32);

impl Deref for DbInputIndex {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<OperatorIdx> for DbInputIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<i64> for DbInputIndex {
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

impl sqlx::Type<Sqlite> for DbDutyStatus {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbPubNonce(PubNonce);

impl Deref for DbPubNonce {
    type Target = PubNonce;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<PubNonce> for DbPubNonce {
    fn from(value: PubNonce) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbPubNonce {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbPubNonce {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let pubnonce_str: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let pubnonce = PubNonce::from_str(&pubnonce_str)
            .map_err(|_| sqlx::Error::Decode("Failed to decode pubnonce".into()))?;
        Ok(Self(pubnonce))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbPubNonce {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let pubnonce_str = self.0.to_string();

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&pubnonce_str, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbSecNonce(SecNonce);

impl Deref for DbSecNonce {
    type Target = SecNonce;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SecNonce> for DbSecNonce {
    fn from(value: SecNonce) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbSecNonce {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <Vec<u8> as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbSecNonce {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let secnonce_bytes: Vec<u8> = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let secnonce = SecNonce::from_bytes(&secnonce_bytes)
            .map_err(|_| sqlx::Error::Decode("Failed to decode secnonce".into()))?;
        Ok(Self(secnonce))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbSecNonce {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let secnonce_bytes = self.0.to_bytes().to_vec();

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&secnonce_bytes, buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbPartialSig(PartialSignature);

impl Deref for DbPartialSig {
    type Target = PartialSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<PartialSignature> for DbPartialSig {
    fn from(value: PartialSignature) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbPartialSig {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbPartialSig {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let partial_sig_str: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let partial_sig = PartialSignature::from_str(&partial_sig_str)
            .map_err(|_| sqlx::Error::Decode("Failed to decode partial sig".into()))?;
        Ok(Self(partial_sig))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbPartialSig {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let partial_sig_str = self.0.serialize().to_lower_hex_string();

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&partial_sig_str, buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbScriptBuf(ScriptBuf);

impl Deref for DbScriptBuf {
    type Target = ScriptBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ScriptBuf> for DbScriptBuf {
    fn from(value: ScriptBuf) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbScriptBuf {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for DbScriptBuf {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let script_hex: String = sqlx::decode::Decode::<'r, Sqlite>::decode(value)?;
        let script = consensus::encode::deserialize_hex(&script_hex)
            .map_err(|_| sqlx::Error::Decode("Failed to decode ScriptBuf".into()))?;
        Ok(Self(script))
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for DbScriptBuf {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let script_hex = consensus::encode::serialize_hex(&self.0);

        sqlx::Encode::<'q, Sqlite>::encode_by_ref(&script_hex, buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbAmount(Amount);

impl Deref for DbAmount {
    type Target = Amount;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Amount> for DbAmount {
    fn from(value: Amount) -> Self {
        Self(value)
    }
}

impl sqlx::Type<Sqlite> for DbAmount {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<Sqlite>>::type_info()
    }
}

impl sqlx::Decode<'_, Sqlite> for DbAmount {
    fn decode(value: SqliteValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let satoshis: i64 = sqlx::decode::Decode::<'_, Sqlite>::decode(value)?;
        let amount = Amount::from_sat(satoshis as u64);
        Ok(Self(amount))
    }
}

impl sqlx::Encode<'_, Sqlite> for DbAmount {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let satoshis = self.0.to_sat() as i64;
        sqlx::Encode::<'_, Sqlite>::encode_by_ref(&satoshis, buf)
    }
}

#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Serialize, Deserialize)]
pub struct JoinedKickoffInfo {
    pub ki_txid: DbTxid,
    pub ki_change_address: String,
    pub ki_change_address_network: String,
    pub ki_change_amount: DbAmount,
    pub fi_input_txid: Option<DbTxid>,
    pub fi_vout: Option<u32>,
    pub fu_value: Option<DbAmount>,
    pub fu_script_pubkey: Option<DbScriptBuf>,
}