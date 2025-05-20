use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use bitcoin::Txid;
use bitvm::{
    chunk::api::{
        Assertions as g16Assertions, PublicKeys as g16PublicKeys, Signatures as g16Signatures,
        NUM_HASH, NUM_PUBS, NUM_U256,
    },
    signatures::wots_api::{wots256, wots_hash},
};
use proptest::prelude::{any, Arbitrary, BoxedStrategy, Strategy};
use proptest_derive::Arbitrary;
use serde::{de::Visitor, ser::SerializeSeq, Deserialize, Serialize};

use crate::scripts::{
    commitments::{
        get_deposit_master_secret_key, secret_key_for_bridge_out_txid, secret_key_for_proof_element,
    },
    prelude::secret_key_for_public_inputs_hash,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256PublicKey(pub wots256::PublicKey);

impl Wots256PublicKey {
    /// Creates a new 256-bit WOTS public key from a secret key string.
    pub fn new(msk: &str, txid: Txid) -> Self {
        let sk = get_deposit_master_secret_key(msk, txid);

        Self(wots256::generate_public_key(
            &secret_key_for_bridge_out_txid(&sk),
        ))
    }
}

impl From<strata_p2p_types::Wots256PublicKey> for Wots256PublicKey {
    fn from(value: strata_p2p_types::Wots256PublicKey) -> Self {
        Self(value.0)
    }
}

impl From<Wots256PublicKey> for strata_p2p_types::Wots256PublicKey {
    fn from(value: Wots256PublicKey) -> Self {
        strata_p2p_types::Wots256PublicKey::new(value.0)
    }
}

impl Serialize for Wots256PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut structure =
            serializer.serialize_seq(Some(std::mem::size_of::<Wots256PublicKey>()))?;
        for key in self.0 {
            for byte in key {
                structure.serialize_element(&byte)?;
            }
        }
        structure.end()
    }
}

impl<'de> Deserialize<'de> for Wots256PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Wots256PublicKeyVisitor;

        impl<'de> Visitor<'de> for Wots256PublicKeyVisitor {
            type Value = Wots256PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&format!(
                    "a flattened structure of type [[u8; 20]; {}]",
                    wots_key_width(256)
                ))
            }

            // Handle the case where input is a sequence (e.g., JSON array)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut packed = [[0u8; 20]; wots_key_width(256)];
                for (key_idx, key) in packed.iter_mut().enumerate() {
                    for (byte_idx, byte) in key.iter_mut().enumerate() {
                        if let Some(next) = seq.next_element()? {
                            *byte = next;
                        } else {
                            return Err(serde::de::Error::invalid_length(
                                (key_idx + 1) * (byte_idx + 1),
                                &self,
                            ));
                        }
                    }
                }

                Ok(Wots256PublicKey(packed))
            }
        }

        deserializer.deserialize_seq(Wots256PublicKeyVisitor)
    }
}

impl Arbitrary for Wots256PublicKey {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<[u8; std::mem::size_of::<Wots256PublicKey>()]>()
            .no_shrink()
            .prop_map(|arr| unsafe { std::mem::transmute(arr) })
            .boxed()
    }

    type Strategy = BoxedStrategy<Wots256PublicKey>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WotsHashPublicKey(pub wots_hash::PublicKey);

impl From<strata_p2p_types::Wots128PublicKey> for WotsHashPublicKey {
    fn from(value: strata_p2p_types::Wots128PublicKey) -> Self {
        Self(value.0)
    }
}

impl From<WotsHashPublicKey> for strata_p2p_types::Wots128PublicKey {
    fn from(value: WotsHashPublicKey) -> Self {
        strata_p2p_types::Wots128PublicKey::new(value.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16PublicKeys(pub g16PublicKeys);

// should probably not do this but `g16PublicKeys` is already a tuple, so these impls make the
// tuple access more ergonomic.
impl Deref for Groth16PublicKeys {
    type Target = g16PublicKeys;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Groth16PublicKeys {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<strata_p2p_types::Groth16PublicKeys> for Groth16PublicKeys {
    type Error = String;

    fn try_from(g16_keys: strata_p2p_types::Groth16PublicKeys) -> Result<Self, Self::Error> {
        if g16_keys.public_inputs.len() != NUM_PUBS {
            return Err(format!(
                "Could not convert groth 16 keys: invalid length of public inputs ({})",
                g16_keys.public_inputs.len()
            ));
        }
        let public_inputs = std::array::from_fn(|i| *g16_keys.public_inputs[i]);

        if g16_keys.fqs.len() != NUM_U256 {
            return Err(format!(
                "Could not convert groth 16 keys: invalid length of fqs ({})",
                g16_keys.fqs.len()
            ));
        }
        let fqs = std::array::from_fn(|i| *g16_keys.fqs[i]);

        if g16_keys.hashes.len() != NUM_HASH {
            return Err(format!(
                "Could not convert groth 16 keys: invalid length of hashes ({})",
                g16_keys.hashes.len()
            ));
        }
        let hashes = std::array::from_fn(|i| *g16_keys.hashes[i]);

        Ok(Self((public_inputs, fqs, hashes)))
    }
}

impl From<Groth16PublicKeys> for strata_p2p_types::Groth16PublicKeys {
    fn from(value: Groth16PublicKeys) -> Self {
        let (public_inputs, fqs, hashes) = value.0;

        Self::new(
            public_inputs
                .map(strata_p2p_types::Wots256PublicKey::new)
                .into_iter()
                .collect(),
            fqs.map(strata_p2p_types::Wots256PublicKey::new)
                .into_iter()
                .collect(),
            hashes
                .map(strata_p2p_types::Wots128PublicKey::new)
                .into_iter()
                .collect(),
        )
    }
}

impl Serialize for Groth16PublicKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut structure = serializer.serialize_seq(Some(std::mem::size_of::<Self>()))?;
        let inner = self.0;
        let public_inputs = inner.0;
        let fqs = inner.1;
        let hashes = inner.2;
        for input in public_inputs {
            for key in input {
                for byte in key {
                    structure.serialize_element(&byte)?;
                }
            }
        }
        for fq in fqs {
            for key in fq {
                for byte in key {
                    structure.serialize_element(&byte)?;
                }
            }
        }
        for hash in hashes {
            for key in hash {
                for byte in key {
                    structure.serialize_element(&byte)?;
                }
            }
        }

        structure.end()
    }
}

impl<'de> Deserialize<'de> for Groth16PublicKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Create a visitor for our nested array
        struct Groth16PublicKeysVisitor;

        impl<'de> Visitor<'de> for Groth16PublicKeysVisitor {
            type Value = Groth16PublicKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let wots_256_key_width = wots_key_width(256);
                let wots_128_key_width = wots_key_width(128);
                formatter.write_str(&format!(
                    "a flattened structure of type ([[[u8; 20]; {wots_256_key_width}]; NUM_PUBS], [[[u8; 20]; {wots_256_key_width}]; NUM_U256], [[[u8; 20]; {wots_128_key_width}]; NUM_HASHES])"
                ))
            }

            // Handle the case where input is a sequence (e.g., JSON array)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut public_inputs = [[[0u8; 20]; wots_key_width(256)]; NUM_PUBS];
                for (input_idx, input) in public_inputs.iter_mut().enumerate() {
                    for (key_idx, key) in input.iter_mut().enumerate() {
                        for (byte_idx, byte) in key.iter_mut().enumerate() {
                            if let Some(next) = seq.next_element()? {
                                *byte = next;
                            } else {
                                return Err(serde::de::Error::invalid_length(
                                    (input_idx + 1) * (key_idx + 1) * (byte_idx + 1),
                                    &self,
                                ));
                            }
                        }
                    }
                }

                let mut fqs = [[[0u8; 20]; wots_key_width(256)]; NUM_U256];
                for (fq_idx, fq) in fqs.iter_mut().enumerate() {
                    for (key_idx, key) in fq.iter_mut().enumerate() {
                        for (byte_idx, byte) in key.iter_mut().enumerate() {
                            if let Some(next) = seq.next_element()? {
                                *byte = next;
                            } else {
                                return Err(serde::de::Error::invalid_length(
                                    (fq_idx + 1) * (key_idx + 1) * (byte_idx + 1),
                                    &self,
                                ));
                            }
                        }
                    }
                }

                let mut hashes = [[[0u8; 20]; wots_key_width(128)]; NUM_HASH];
                for (hash_idx, hash) in hashes.iter_mut().enumerate() {
                    for (key_idx, key) in hash.iter_mut().enumerate() {
                        for (byte_idx, byte) in key.iter_mut().enumerate() {
                            if let Some(next) = seq.next_element()? {
                                *byte = next;
                            } else {
                                return Err(serde::de::Error::invalid_length(
                                    (hash_idx + 1) * (key_idx + 1) * (byte_idx + 1),
                                    &self,
                                ));
                            }
                        }
                    }
                }

                Ok(Groth16PublicKeys((public_inputs, fqs, hashes)))
            }
        }

        deserializer.deserialize_seq(Groth16PublicKeysVisitor)
    }
}
impl Arbitrary for Groth16PublicKeys {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<[u8; std::mem::size_of::<Groth16PublicKeys>()]>()
            .no_shrink()
            .prop_map(|arr| unsafe { std::mem::transmute(arr) })
            .boxed()
    }

    type Strategy = BoxedStrategy<Groth16PublicKeys>;
}

impl Groth16PublicKeys {
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self((
            [wots256::generate_public_key(
                &secret_key_for_public_inputs_hash(&deposit_msk),
            )],
            std::array::from_fn(|i| {
                wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i))
            }),
            std::array::from_fn(|i| {
                wots_hash::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i + 40))
            }),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256Signature(pub wots256::Signature);

impl Wots256Signature {
    pub fn new(msk: &str, seed_txid: Txid, data: &[u8; 32]) -> Self {
        let sk = get_deposit_master_secret_key(msk, seed_txid);

        Self(wots256::get_signature(
            &secret_key_for_bridge_out_txid(&sk),
            data,
        ))
    }
}

impl Deref for Wots256Signature {
    type Target = wots256::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16Signatures(pub g16Signatures);

impl Deref for Groth16Signatures {
    type Target = g16Signatures;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Groth16Signatures {
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self((
            [wots256::get_signature(
                &secret_key_for_public_inputs_hash(&deposit_msk),
                &assertions.groth16.0[0],
            )]
            .into(),
            std::array::from_fn(|i| {
                wots256::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i),
                    &assertions.groth16.1[i],
                )
            })
            .into(),
            std::array::from_fn(|i| {
                wots_hash::get_signature(
                    &secret_key_for_proof_element(&deposit_msk, i + 40),
                    &assertions.groth16.2[i],
                )
            })
            .into(),
        ))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Serialize,
    Deserialize,
    Arbitrary,
)]
pub struct PublicKeys {
    pub withdrawal_fulfillment: Wots256PublicKey,
    pub groth16: Groth16PublicKeys,
}

impl PublicKeys {
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        Self {
            withdrawal_fulfillment: Wots256PublicKey::new(msk, deposit_txid),
            groth16: Groth16PublicKeys::new(msk, deposit_txid),
        }
    }
}

impl TryFrom<strata_p2p_types::WotsPublicKeys> for PublicKeys {
    type Error = String;

    fn try_from(value: strata_p2p_types::WotsPublicKeys) -> Result<Self, Self::Error> {
        let withdrawal_fulfillment = value.withdrawal_fulfillment.into();

        let groth16 = value.groth16.try_into()?;

        Ok(Self {
            withdrawal_fulfillment,
            groth16,
        })
    }
}

impl From<PublicKeys> for strata_p2p_types::WotsPublicKeys {
    fn from(value: PublicKeys) -> Self {
        Self {
            withdrawal_fulfillment: value.withdrawal_fulfillment.into(),
            groth16: value.groth16.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Signatures {
    pub withdrawal_fulfillment: Wots256Signature,
    pub groth16: Groth16Signatures,
}

impl Signatures {
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        Self {
            withdrawal_fulfillment: Wots256Signature::new(
                msk,
                deposit_txid,
                &assertions.withdrawal_fulfillment,
            ),
            groth16: Groth16Signatures::new(msk, deposit_txid, assertions),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Assertions {
    pub withdrawal_fulfillment: [u8; 32],
    pub groth16: g16Assertions,
}

const WINTERNITZ_DIGIT_WIDTH: usize = 4;

/// Calculates the total WOTS key width based off of the number of bits in the message being signed
/// and the number of bits per WOTS digit.
const fn wots_key_width(num_bits: usize) -> usize {
    let num_digits = num_bits.div_ceil(WINTERNITZ_DIGIT_WIDTH);
    num_digits + checksum_width(num_bits, WINTERNITZ_DIGIT_WIDTH)
}

/// Calculates the total WOTS key digits used for the checksum.
const fn checksum_width(num_bits: usize, digit_width: usize) -> usize {
    let num_digits = num_bits.div_ceil(digit_width);
    let max_digit = (2 << digit_width) - 1;
    let max_checksum = num_digits * max_digit;
    let checksum_bytes = log_base_ceil(max_checksum as u32, 256) as usize;
    (checksum_bytes * 8).div_ceil(digit_width)
}

/// Calculates ceil(log_base(n))
pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}
