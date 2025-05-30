//! Descriptor parsing utilities.

use std::{fs, path::Path};

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use secp256k1::{Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};
use strata_bridge_primitives::types::OperatorIdx;
use strata_primitives::bridge::PublickeyTable;
use tracing::info;

const DERIV_BASE_IDX: u32 = 56;
const DERIV_OP_IDX: u32 = 20;
const DERIV_OP_SIGNING_IDX: u32 = 100;
const DERIV_OP_WALLET_IDX: u32 = 101;

/// Derives the signing and wallet xprivs for a Strata operator.
pub fn derive_op_purpose_xprivs(root: &Xpriv) -> anyhow::Result<(Xpriv, Xpriv)> {
    let signing_path = DerivationPath::master().extend([
        ChildNumber::from_hardened_idx(DERIV_BASE_IDX).unwrap(),
        ChildNumber::from_hardened_idx(DERIV_OP_IDX).unwrap(),
        ChildNumber::from_normal_idx(DERIV_OP_SIGNING_IDX).unwrap(),
    ]);

    let wallet_path = DerivationPath::master().extend([
        ChildNumber::from_hardened_idx(DERIV_BASE_IDX).unwrap(),
        ChildNumber::from_hardened_idx(DERIV_OP_IDX).unwrap(),
        ChildNumber::from_normal_idx(DERIV_OP_WALLET_IDX).unwrap(),
    ]);

    let signing_xpriv = root.derive_priv(bitcoin::secp256k1::SECP256K1, &signing_path)?;
    let wallet_xpriv = root.derive_priv(bitcoin::secp256k1::SECP256K1, &wallet_path)?;

    Ok((signing_xpriv, wallet_xpriv))
}

/// Loads the keypairs and xprivs from the xpriv file.
pub fn get_keypairs_and_load_xpriv(
    xpriv_file: impl AsRef<Path>,
    pubkey_table: &PublickeyTable,
) -> Vec<(OperatorIdx, Keypair)> {
    let xprivs = fs::read_to_string(xpriv_file).expect("must be able to read xpriv file");

    let mut indexes_and_keypairs: Vec<(OperatorIdx, Keypair)> =
        Vec::with_capacity(pubkey_table.0.len());

    for xpriv_str in xprivs.lines() {
        // Get the keypair after deriving the wallet xpriv.
        let master_xpriv = xpriv_str.parse::<Xpriv>().expect("could not parse xpriv");
        let (_, wallet_xpriv) = derive_op_purpose_xprivs(&master_xpriv)
            .expect("should be able to derive xprivs from master xpriv");

        let mut keypair = wallet_xpriv.to_keypair(SECP256K1);
        let mut sk = SecretKey::from_keypair(&keypair);

        // adjust for parity, which should always be even
        let (_, parity) = XOnlyPublicKey::from_keypair(&keypair);
        if matches!(parity, Parity::Odd) {
            sk = sk.negate();
            keypair = Keypair::from_secret_key(SECP256K1, &sk);
        };

        let pubkey = PublicKey::from_secret_key(SECP256K1, &sk);

        // Get this client's pubkey from the bitcoin wallet.
        let own_index: OperatorIdx = pubkey_table
            .0
            .iter()
            .find_map(|(id, pk)| if pk == &pubkey { Some(*id) } else { None })
            .expect("could not find this operator's pubkey in the rollup pubkey table");

        indexes_and_keypairs.push((own_index, keypair));
    }

    info!(event = "parsed keypairs and operator indexes", operator_count=%indexes_and_keypairs.len());

    indexes_and_keypairs
}
