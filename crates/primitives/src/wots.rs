use std::ops::{Deref, DerefMut};

use bitcoin::Txid;
use bitvm::{
    groth16::g16::{self},
    signatures::wots_api::{wots160, wots256},
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
    pub fn new(sk: &str) -> Self {
        Self(wots256::generate_public_key(
            &secret_key_for_bridge_out_txid(sk),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots160PublicKey(pub wots160::PublicKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16PublicKeys(pub g16::PublicKeys);

// should probably not do this but `g16::PublicKeys` is already a tuple, so these impls make the
// tuple access more ergonomic.
impl Deref for Groth16PublicKeys {
    type Target = g16::PublicKeys;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Groth16PublicKeys {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PublicKeys {
    pub withdrawal_fulfillment_pk: Wots256PublicKey,

    pub groth16: Groth16PublicKeys,
}

impl PublicKeys {
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);
        Self {
            withdrawal_fulfillment_pk: Wots256PublicKey(wots256::generate_public_key(
                &secret_key_for_bridge_out_txid(&deposit_msk),
            )),
            groth16: Groth16PublicKeys((
                [wots256::generate_public_key(
                    &secret_key_for_public_inputs_hash(&deposit_msk),
                )],
                std::array::from_fn(|i| {
                    wots256::generate_public_key(&secret_key_for_proof_element(&deposit_msk, i))
                }),
                std::array::from_fn(|i| {
                    wots160::generate_public_key(&secret_key_for_proof_element(
                        &deposit_msk,
                        i + 40,
                    ))
                }),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256Signature(wots256::Signature);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16Signatures(g16::Signatures);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Signatures {
    pub withdrawal_fulfillment_sig: wots256::Signature,
    pub groth16: g16::Signatures,
}

impl Signatures {
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self {
            withdrawal_fulfillment_sig: wots256::get_signature(
                &secret_key_for_bridge_out_txid(&deposit_msk),
                &assertions.bridge_out_txid,
            ),
            groth16: (
                [wots256::get_signature(
                    &secret_key_for_public_inputs_hash(&deposit_msk),
                    &assertions.groth16.0[0],
                )],
                std::array::from_fn(|i| {
                    wots256::get_signature(
                        &secret_key_for_proof_element(&deposit_msk, i),
                        &assertions.groth16.1[i],
                    )
                }),
                std::array::from_fn(|i| {
                    wots160::get_signature(
                        &secret_key_for_proof_element(&deposit_msk, i + 40),
                        &assertions.groth16.2[i],
                    )
                }),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Assertions {
    pub bridge_out_txid: [u8; 32],
    pub groth16: g16::Assertions,
}
