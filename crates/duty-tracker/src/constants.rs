//! Constants used throughout the duty tracker.

// FIXME: (@Rajil1213) find a better way to do this instead of baking non-obvious values.

use bitvm::chunk::api::NUM_PUBS;

/// The index used to get the 256-bit WOTS public key from the s2 server for committing to the
/// withdrawal fulfillment txid in the Claim transaction.
pub(super) const WITHDRAWAL_FULFILLMENT_PK_IDX: u32 = 0;

/// The offset used to construct the array of 256-bit WOTS public keys required to commit to the
/// public params of the proof.
///
/// This has a value of 1 because the index 0 is used in [`WITHDRAWAL_FULFILLMENT_PK_IDX`].
#[expect(dead_code)] // will be used during assertion impl
pub(super) const PUBLIC_INPUTS_PK_OFFSET: usize = 1;

/// The offset used to construct the array of 256-bit WOTS public keys required to commit to the
/// field elements of the proof assertion.
#[expect(dead_code)] // will be used during assertion impl
pub(super) const FIELD_ELEMENTS_PK_OFFSET: usize = 1 + NUM_PUBS; // 1 for the withdrawal fulfillment

/// The offset used to construct the array of WOTS public keys required to commit to the hash
/// elements of the proof assertion.
///
/// This has an offset of 0 because no other hash elements are generated separately in the proof
/// assertion.
#[expect(dead_code)] // will be used during assertion impl
pub(super) const HASH_ELEMENTS_PK_OFFSET: usize = 0;
