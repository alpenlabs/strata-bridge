//! WOTS primitives.

#![allow(missing_docs)] // rkyv macros are not nice at generating docs from docstrings.

use std::{fmt, marker::PhantomData, ops::Deref, sync::Arc};

use bitcoin::Txid;
use bitvm::{
    chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256},
    signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256},
};
use proptest::prelude::{any, Arbitrary, BoxedStrategy, Strategy};
use proptest_derive::Arbitrary;
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use strata_p2p_types::WotsPublicKeys;

use crate::scripts::{
    commitments::{
        get_deposit_master_secret_key, secret_key_for_bridge_out_txid, secret_key_for_proof_element,
    },
    prelude::secret_key_for_public_inputs_hash,
};

pub type BitVmG16PublicKeys = (
    [<wots256 as Wots>::PublicKey; NUM_PUBS],
    [<wots256 as Wots>::PublicKey; NUM_U256],
    [<wots_hash as Wots>::PublicKey; NUM_HASH],
);

pub type BitVmG16Sigs = (
    Box<[<wots256 as Wots>::Signature; 1]>,
    Box<[<wots256 as Wots>::Signature; 14]>,
    Box<[<wots_hash as Wots>::Signature; 363]>,
);

pub type BitVmG16Assertions = (
    [[u8; 32]; NUM_PUBS],
    [[u8; 32]; NUM_U256],
    [[u8; 16]; NUM_HASH],
);

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256PublicKey(pub Arc<<wots256 as Wots>::PublicKey>);

impl Wots256PublicKey {
    /// Creates a new 256-bit WOTS public key from a secret key string.
    pub fn new(msk: &str, txid: Txid) -> Self {
        let sk = get_deposit_master_secret_key(msk, txid);

        Self(Arc::new(<wots256 as Wots>::generate_public_key(
            &secret_key_for_bridge_out_txid(&sk),
        )))
    }
}

impl From<strata_p2p_types::Wots256PublicKey> for Wots256PublicKey {
    fn from(value: strata_p2p_types::Wots256PublicKey) -> Self {
        Self(Arc::new(value.0))
    }
}

impl From<Wots256PublicKey> for strata_p2p_types::Wots256PublicKey {
    fn from(value: Wots256PublicKey) -> Self {
        strata_p2p_types::Wots256PublicKey::new(*value.0)
    }
}

impl Serialize for Wots256PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut structure =
            serializer.serialize_seq(Some(std::mem::size_of::<Wots256PublicKey>()))?;
        for key in *self.0 {
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
        D: Deserializer<'de>,
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
                A: de::SeqAccess<'de>,
            {
                let mut packed = [[0u8; 20]; wots_key_width(256)];
                for (key_idx, key) in packed.iter_mut().enumerate() {
                    for (byte_idx, byte) in key.iter_mut().enumerate() {
                        if let Some(next) = seq.next_element()? {
                            *byte = next;
                        } else {
                            return Err(de::Error::invalid_length(
                                (key_idx + 1) * (byte_idx + 1),
                                &self,
                            ));
                        }
                    }
                }

                Ok(Wots256PublicKey(Arc::new(packed)))
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

/// A 128-bit WOTS public key used for hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WotsHashPublicKey(pub <wots_hash as Wots>::PublicKey);

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

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16PublicKeys(pub Arc<BitVmG16PublicKeys>);

// should probably not do this but `G16PublicKeys` is already a tuple, so these impls make the
// tuple access more ergonomic.
impl Deref for Groth16PublicKeys {
    type Target = Arc<BitVmG16PublicKeys>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<strata_p2p_types::Groth16PublicKeys> for Groth16PublicKeys {
    type Error = (String, strata_p2p_types::Groth16PublicKeys);

    fn try_from(g16_keys: strata_p2p_types::Groth16PublicKeys) -> Result<Self, Self::Error> {
        if g16_keys.public_inputs.len() != NUM_PUBS {
            return Err((
                format!(
                    "Could not convert groth 16 keys: invalid length of public inputs ({})",
                    g16_keys.public_inputs.len()
                ),
                g16_keys,
            ));
        }
        let public_inputs = std::array::from_fn(|i| *g16_keys.public_inputs[i]);

        if g16_keys.fqs.len() != NUM_U256 {
            return Err((
                format!(
                    "Could not convert groth 16 keys: invalid length of fqs ({})",
                    g16_keys.fqs.len()
                ),
                g16_keys,
            ));
        }
        let fqs = std::array::from_fn(|i| *g16_keys.fqs[i]);

        if g16_keys.hashes.len() != NUM_HASH {
            return Err((
                format!(
                    "Could not convert groth 16 keys: invalid length of hashes ({})",
                    g16_keys.hashes.len()
                ),
                g16_keys,
            ));
        }
        let hashes = std::array::from_fn(|i| *g16_keys.hashes[i]);

        Ok(Self(Arc::new((public_inputs, fqs, hashes))))
    }
}

impl From<Groth16PublicKeys> for strata_p2p_types::Groth16PublicKeys {
    fn from(value: Groth16PublicKeys) -> Self {
        let (public_inputs, fqs, hashes) = *value.0;

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
        S: Serializer,
    {
        let mut structure = serializer.serialize_seq(Some(std::mem::size_of::<Self>()))?;
        let inner = *self.0;
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
        D: Deserializer<'de>,
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
                A: de::SeqAccess<'de>,
            {
                let mut public_inputs = [[[0u8; 20]; wots_key_width(256)]; NUM_PUBS];
                for (input_idx, input) in public_inputs.iter_mut().enumerate() {
                    for (key_idx, key) in input.iter_mut().enumerate() {
                        for (byte_idx, byte) in key.iter_mut().enumerate() {
                            if let Some(next) = seq.next_element()? {
                                *byte = next;
                            } else {
                                return Err(de::Error::invalid_length(
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
                                return Err(de::Error::invalid_length(
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
                                return Err(de::Error::invalid_length(
                                    (hash_idx + 1) * (key_idx + 1) * (byte_idx + 1),
                                    &self,
                                ));
                            }
                        }
                    }
                }

                Ok(Groth16PublicKeys(Arc::new((public_inputs, fqs, hashes))))
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
    /// Creates a new set of Groth16 public keys from a master secret key and a deposit transaction
    /// ID.
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self(Arc::new((
            [wots256::generate_public_key(
                &secret_key_for_public_inputs_hash(&deposit_msk),
            )],
            std::array::from_fn(|i| {
                wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i))
            }),
            std::array::from_fn(|i| {
                wots_hash::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i + 40))
            }),
        )))
    }
}

/// A stub for the WOTS signature, used for serialization.
///
/// All the wots signatures defined here and used in this codebase have this structure i.e., each
/// signature is an array of tuples of a 20-byte preimage and a digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WotsSigStub<const N: usize>([[u8; 21]; N]);

impl<const N: usize> Serialize for WotsSigStub<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for item in &self.0 {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de, const N: usize> Deserialize<'de> for WotsSigStub<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<const N: usize> {
            marker: PhantomData<[([u8; 20], u8); N]>,
        }

        impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
            type Value = WotsSigStub<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of {N} [u8; 21] arrays")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(N);
                for _ in 0..N {
                    let item: [u8; 21] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(items.len(), &self))?;
                    items.push(item);
                }
                let arr: [[u8; 21]; N] = items
                    .try_into()
                    .map_err(|_| de::Error::custom("invalid array length"))?;

                Ok(WotsSigStub(arr))
            }
        }

        deserializer.deserialize_seq(ArrayVisitor {
            marker: PhantomData,
        })
    }
}

/// A 256-bit WOTS signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256Sig(pub <wots256 as Wots>::Signature);

impl Wots256Sig {
    /// Creates a new 256-bit WOTS signature from a master secret key, a seed transaction ID, and
    /// data to sign.
    pub fn new(msk: &str, seed_txid: Txid, data: &[u8; 32]) -> Self {
        let sk = get_deposit_master_secret_key(msk, seed_txid);

        Self(<wots256 as Wots>::sign(
            &secret_key_for_bridge_out_txid(&sk),
            data,
        ))
    }
}

impl Deref for Wots256Sig {
    type Target = <wots256 as Wots>::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// WOTS signatures used for Groth16 proofs.
impl Serialize for Wots256Sig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WotsSigStub(self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Wots256Sig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wots_signature = WotsSigStub::deserialize(deserializer)?;
        Ok(Self(wots_signature.0))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WotsHashSig(<wots_hash as Wots>::Signature);

impl Serialize for WotsHashSig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WotsSigStub(self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WotsHashSig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wots_signature = WotsSigStub::deserialize(deserializer)?;
        Ok(Self(wots_signature.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16Sigs(pub BitVmG16Sigs);

impl Deref for Groth16Sigs {
    type Target = BitVmG16Sigs;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Groth16Sigs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (pub_inputs, field_elems, hashes) = &self.0;

        let pub_inputs = pub_inputs.map(WotsSigStub);
        let field_elems = field_elems.map(WotsSigStub);
        let hashes = hashes.map(WotsSigStub);

        (pub_inputs, field_elems, &hashes[..]).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Groth16Sigs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (pub_inputs, field_elems, hashes): (
            [Wots256Sig; NUM_PUBS],
            [Wots256Sig; NUM_U256],
            Vec<WotsHashSig>, /* vec because its length is longer than what is supported
                               * by serde */
        ) = Deserialize::deserialize(deserializer)?;

        if hashes.len() != NUM_HASH {
            return Err(de::Error::custom(format!(
                "Invalid length of hashes, got: {}, expected: {NUM_HASH}",
                hashes.len(),
            )));
        }

        let pub_inputs = pub_inputs.map(|val| val.0);
        let field_elems = field_elems.map(|val| val.0);
        let hashes = std::array::from_fn(|i| hashes[i].0);

        Ok(Self((
            Box::new(pub_inputs),
            Box::new(field_elems),
            Box::new(hashes),
        )))
    }
}

impl Groth16Sigs {
    /// Creates a new set of Groth16 signatures from a master secret key, a deposit transaction
    /// ID, and assertions.
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self((
            [wots256::sign(
                &secret_key_for_public_inputs_hash(&deposit_msk),
                &assertions.groth16.0[0],
            )]
            .into(),
            std::array::from_fn(|i| {
                wots256::sign(
                    &secret_key_for_proof_element(&deposit_msk, i),
                    &assertions.groth16.1[i],
                )
            })
            .into(),
            std::array::from_fn(|i| {
                wots_hash::sign(
                    &secret_key_for_proof_element(&deposit_msk, i + 40),
                    &assertions.groth16.2[i],
                )
            })
            .into(),
        ))
    }
}

/// Groth16 public keys.
#[derive(
    Debug,
    Clone,
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
    /// The WOTS public key for the withdrawal fulfillment.
    pub withdrawal_fulfillment: Wots256PublicKey,

    /// The Groth16 public keys.
    pub groth16: Groth16PublicKeys,
}

impl PublicKeys {
    /// Creates a new set of WOTS public keys from a master secret key and a deposit transaction
    /// ID.
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        Self {
            withdrawal_fulfillment: Wots256PublicKey::new(msk, deposit_txid),
            groth16: Groth16PublicKeys::new(msk, deposit_txid),
        }
    }
}

impl TryFrom<strata_p2p_types::WotsPublicKeys> for PublicKeys {
    type Error = (String, strata_p2p_types::WotsPublicKeys);

    fn try_from(value: strata_p2p_types::WotsPublicKeys) -> Result<Self, Self::Error> {
        let groth16 = value.groth16.try_into().map_err(
            |e: (String, strata_p2p_types::Groth16PublicKeys)| {
                (
                    e.0,
                    WotsPublicKeys {
                        withdrawal_fulfillment: value.withdrawal_fulfillment,
                        groth16: e.1,
                    },
                )
            },
        )?;

        let withdrawal_fulfillment = value.withdrawal_fulfillment.into();

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

/// WOTS signatures used for withdrawal fulfillment.
#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Signatures {
    /// The WOTS signature for the withdrawal fulfillment.
    pub withdrawal_fulfillment: Wots256Sig,

    /// The Groth16 signatures.
    pub groth16: Groth16Sigs,
}

impl Signatures {
    /// Creates a new set of WOTS signatures from a master secret key, a deposit transaction ID,
    /// and assertions.
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        Self {
            withdrawal_fulfillment: Wots256Sig::new(
                msk,
                deposit_txid,
                &assertions.withdrawal_fulfillment,
            ),
            groth16: Groth16Sigs::new(msk, deposit_txid, assertions),
        }
    }
}

/// Assertions used for withdrawal fulfillment and Groth16 proofs.
#[derive(Debug, Clone, Copy, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Assertions {
    /// The data to sign for the withdrawal fulfillment.
    pub withdrawal_fulfillment: [u8; 32],

    /// The assertions for the Groth16 proof.
    pub groth16: BitVmG16Assertions,
}

// FIXME: (@Rajil1213) replace these with counterparts from the `wots` crate.
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

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{self, Hash};

    use super::*;

    #[test]
    fn test_generic_wots_sig_serde() {
        let wots_signature = WotsSigStub::<4>([[0u8; 21], [1u8; 21], [2u8; 21], [3u8; 21]]);

        let serialized = serde_json::to_string(&wots_signature).expect("must be able to serialize");
        let deserialized: WotsSigStub<4> =
            serde_json::from_str(&serialized).expect("must be able to deserialize");

        assert_eq!(
            wots_signature, deserialized,
            "roundtrip serialization must succeed"
        );
    }

    #[test]
    fn test_wots256_sig_serde() {
        let msk = "msk";
        let seed_txid = Txid::from_raw_hash(hashes::sha256d::Hash::hash("txid".as_bytes()));
        let data = [0u8; 32];

        let wots_256 = Wots256Sig::new(msk, seed_txid, &data);

        let serialized =
            serde_json::to_string(&wots_256).expect("must be able to serialize wots256");
        let deserialized: Wots256Sig =
            serde_json::from_str(&serialized).expect("must be able to deserialize wots256");

        assert_eq!(
            wots_256, deserialized,
            "roundtrip serialization must succeed"
        );
    }

    #[test]
    fn test_groth16_sig_serde() {
        let msk = "msk";
        let seed_txid = Txid::from_raw_hash(hashes::sha256d::Hash::hash("txid".as_bytes()));
        let assertions = Assertions {
            withdrawal_fulfillment: [0u8; 32],
            groth16: (
                [[1u8; 32]; NUM_PUBS],
                [[2u8; 32]; NUM_U256],
                [[3u8; 16]; NUM_HASH],
            ),
        };

        let groth_16 = Groth16Sigs::new(msk, seed_txid, assertions);

        let serialized =
            serde_json::to_string(&groth_16).expect("must be able to serialize groth16");
        let deserialized: Groth16Sigs =
            serde_json::from_str(&serialized).expect("must be able to deserialize groth16");

        assert_eq!(
            groth_16, deserialized,
            "roundtrip serialization must succeed"
        );
    }
}
