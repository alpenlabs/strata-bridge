//! This module contains helpers related to [`musig1`](musig2).

use musig2::KeyAggContext;
use secp256k1::PublicKey;

use crate::{errors::AggError, scripts::prelude::TaprootWitness};

/// Create a new [`KeyAggContext`] with the provided [`PublicKey`]s and [`TaprootWitness`].
pub fn create_agg_ctx(
    public_keys: impl IntoIterator<Item = PublicKey>,
    witness: &TaprootWitness,
) -> Result<KeyAggContext, AggError> {
    let key_agg_ctx = KeyAggContext::new(public_keys.into_iter())?;

    Ok(match witness {
        TaprootWitness::Key => key_agg_ctx.with_unspendable_taproot_tweak()?,
        TaprootWitness::Script { .. } => key_agg_ctx,
        TaprootWitness::Tweaked { tweak } => key_agg_ctx.with_taproot_tweak(tweak.as_ref())?,
    })
}
