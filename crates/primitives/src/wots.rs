use std::ops::{Deref, DerefMut};

use bitcoin::Txid;
use bitvm::{
    chunk::api::{
        Assertions as g16Assertions, PublicKeys as g16PublicKeys, Signatures as g16Signatures,
        NUM_HASH, NUM_PUBS, NUM_U256,
    },
    signatures::wots_api::{wots256, wots_hash},
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WotsHashPublicKey(pub wots_hash::PublicKey);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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
        let g16_keys = value.groth16;
        let withdrawal_fulfillment = value.withdrawal_fulfillment;
        let withdrawal_fulfillment =
            Wots256PublicKey(std::array::from_fn(|i| withdrawal_fulfillment[i]));

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

        let groth16 = Groth16PublicKeys((public_inputs, fqs, hashes));

        Ok(Self {
            withdrawal_fulfillment,
            groth16,
        })
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
