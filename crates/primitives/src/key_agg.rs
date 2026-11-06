//! Helpers for MuSig2 aggregation and BIP328 aggregate-key derivation.

use musig2::{secp::MaybeScalar, KeyAggContext};
use secp256k1::PublicKey;
use strata_bridge_key_deriv::key_agg::derive_musig_0_0;

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
