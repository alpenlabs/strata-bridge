//! Helpers for MuSig2 aggregation and BIP328 aggregate-key derivation.

use bitcoin::bip32::{ChildNumber, Xpub};
use musig2::{
    secp::{MaybeScalar, Scalar},
    KeyAggContext,
};
use secp256k1::{PublicKey, SECP256K1};

use crate::{errors::AggError, scripts::taproot::TaprootTweak};

/// Create a new [`KeyAggContext`] with the provided [`PublicKey`]s and [`TaprootTweak`].
pub fn create_agg_ctx(
    public_keys: impl IntoIterator<Item = PublicKey>,
    witness: &TaprootTweak,
) -> Result<KeyAggContext, AggError> {
    let key_agg_ctx = KeyAggContext::new(public_keys)?;

    Ok(match witness {
        TaprootTweak::Key { tweak } => {
            if let Some(tweak) = tweak {
                key_agg_ctx.with_taproot_tweak(tweak.as_ref())?
            } else {
                key_agg_ctx.with_unspendable_taproot_tweak()?
            }
        }
        TaprootTweak::Bip328Key { tweak } => {
            let derivation_tweak = derive_musig_0_0(key_agg_ctx.aggregated_pubkey())?.1;
            let ctx = match derivation_tweak {
                MaybeScalar::Valid(tweak) => key_agg_ctx.with_plain_tweak(tweak)?,
                MaybeScalar::Zero => key_agg_ctx,
            };
            match tweak {
                Some(root) => ctx.with_taproot_tweak(root.as_ref())?,
                None => ctx.with_unspendable_taproot_tweak()?,
            }
        }
        TaprootTweak::Script => key_agg_ctx,
    })
}

/// Derives the BIP-328 `/0/0` child of the given aggregate public key.
///
/// This function returns the public key of the resulting `/0/0` child,
/// as well as the tweak that leads from the aggregate public key to the child.
pub fn derive_musig_0_0(
    aggregate_pubkey: PublicKey,
) -> Result<(PublicKey, MaybeScalar), bitcoin::bip32::Error> {
    let child_number = ChildNumber::Normal { index: 0 };
    let mut xpub = Xpub {
        network: bitcoin::NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number,
        public_key: aggregate_pubkey,
        chain_code: "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
            .parse()
            .expect("BIP-328 chain code"),
    };
    let tweak1 = Scalar::from(xpub.ckd_pub_tweak(child_number)?.0);
    xpub = xpub.ckd_pub(SECP256K1, child_number)?;
    let tweak2 = Scalar::from(xpub.ckd_pub_tweak(child_number)?.0);
    xpub = xpub.ckd_pub(SECP256K1, child_number)?;
    Ok((xpub.public_key, tweak1 + tweak2))
}
