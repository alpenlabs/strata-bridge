use std::ops::{Deref, DerefMut};

use bitcoin::Txid;
use bitvm::{
    groth16::g16::{self},
    signatures::wots::{wots160, wots256, wots32},
};

use crate::scripts::{
    commitments::{
        get_deposit_master_secret_key, secret_key_for_bridge_out_txid,
        secret_key_for_proof_element, secret_key_for_superblock_hash,
        secret_key_for_superblock_period_start_ts,
    },
    prelude::secret_key_for_public_inputs_hash,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots256PublicKey(pub wots256::PublicKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots160PublicKey(pub wots160::PublicKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wots32PublicKey(pub wots32::PublicKey);

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
    pub bridge_out_txid: Wots256PublicKey,

    pub superblock_hash: Wots256PublicKey,

    pub superblock_period_start_ts: Wots32PublicKey,

    pub groth16: Groth16PublicKeys,
}

impl PublicKeys {
    pub fn new(msk: &str, deposit_txid: Txid) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);
        Self {
            bridge_out_txid: Wots256PublicKey(wots256::generate_public_key(
                &secret_key_for_bridge_out_txid(&deposit_msk),
            )),
            superblock_hash: Wots256PublicKey(wots256::generate_public_key(
                &secret_key_for_superblock_hash(&deposit_msk),
            )),
            superblock_period_start_ts: Wots32PublicKey(wots32::generate_public_key(
                &secret_key_for_superblock_period_start_ts(&deposit_msk),
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
pub struct Wots32Signature(wots32::Signature);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Groth16Signatures(g16::Signatures);

#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Signatures {
    pub bridge_out_txid: wots256::Signature,
    pub superblock_hash: wots256::Signature,
    pub superblock_period_start_ts: wots32::Signature,
    pub groth16: g16::Signatures,
}

impl Signatures {
    pub fn new(msk: &str, deposit_txid: Txid, assertions: Assertions) -> Self {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        Self {
            bridge_out_txid: wots256::get_signature(
                &secret_key_for_bridge_out_txid(&deposit_msk),
                &assertions.bridge_out_txid,
            ),
            superblock_hash: wots256::get_signature(
                &secret_key_for_superblock_hash(&deposit_msk),
                &assertions.superblock_hash,
            ),
            superblock_period_start_ts: wots32::get_signature(
                &secret_key_for_superblock_period_start_ts(&deposit_msk),
                &assertions.superblock_period_start_ts,
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
    pub superblock_hash: [u8; 32],
    pub superblock_period_start_ts: [u8; 4],
    pub groth16: g16::Assertions,
}
