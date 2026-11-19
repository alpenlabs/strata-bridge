//! Custody of the general funds in a Fireblocks vault.
//!
//! Fireblocks only signs. The node tracks the vault script with a watch-only BDK wallet, so
//! UTXOs, confirmations, and mempool state all come from the operator's own bitcoind, and lease
//! logic is the same as under secret-service custody.
//!
//! ## What the vault holds
//!
//! The default P2WPKH address of a vault account holds:
//! - the funds that the general wallet spends: withdrawal fronting, stake funding, claim refills
//!   and CPFP fees,
//! - the change of those spends, and
//! - each payout paid to [`OperatorWallet::payout_descriptor`](crate::OperatorWallet), which is the
//!   descriptor that the node gossips for a withdrawal or an unstake.
//!
//! The vault holds no other funds. Secret-service holds:
//! - every bridge protocol key, including the keys of anchors and presigned transactions,
//! - the reserved wallet key, and
//! - the general key. The covenant `payout_descriptor` in the params is P2TR, so a presigned-graph
//!   payout pays `tr(general key)`. That output is not in the vault and the watch-only wallet does
//!   not track it. [`FireblocksSigner`] returns `None` for such an input, and the caller signs it
//!   through secret-service.
//!
//! ## Why RAW signing
//!
//! Fireblocks can produce a BTC transaction two ways. The `TRANSFER` + `inputsSelection`
//! flow has Fireblocks build *and broadcast* its own transaction, which is unusable here: a CPFP
//! child spends a foreign Taproot anchor, must be v3/TRUC, has exact outputs, and goes out in a
//! package with its parent. So the vault signer uses **`RAW` signing**: the composer builds the
//! unsigned transaction, and this module sends the sighashes to Fireblocks for ECDSA signing and
//! assembles the witnesses.
//!
//! A RAW request carries digests only, so a policy rule cannot inspect what it approves. The
//! vault needs an auto-approve rule: a request that waits for a human past the signing limit is
//! cancelled. A Cold Wallet workspace signs offline and cannot meet that limit, so only a hot
//! workspace is supported.
//!
//! Fireblocks BTC is ECDSA secp256k1, so vault addresses are **P2WPKH**; funding witnesses are
//! `[DER-sig + SIGHASH_ALL byte, compressed pubkey]`.
//!
//! ## Request identity
//!
//! A retry of an unchanged transaction must not start a second MPC run while a first one can still
//! finish. The `externalTxId` of a request is therefore `<hash>-<generation>`, where `hash` is the
//! SHA-256 of the sorted sighashes. Fireblocks rejects a repeated id and keeps the request, so a
//! failed create looks up the id and polls the request that it finds. This covers a restart, a
//! create whose response was lost, and a give-up whose cancel failed.
//!
//! A give-up cancels the request, because the next attempt often signs other digests: the fee rate
//! moves. An id stays taken after its request ends, so a sighash set moves to the next generation
//! when it finds a request that ended: `REJECTED`, `BLOCKED`, `FAILED`, `CANCELLED` or `TIMEOUT`.
//! Fireblocks holds this record, so the node persists no counter. A policy refusal therefore costs
//! one refused request per retry of the duty, and a corrected policy applies at the next retry.
//!
//! `CANCELLED` is a dead request, whoever cancelled it. The vendor gives a cancel from the node and
//! a cancel from the console one substatus, `CANCELLED_BY_USER`, so a cancel by a person does not
//! stop the node.
//!
//! ## Startup check
//!
//! [`CheckedVault::check`] gives the value that
//! [`GeneralCustody::Fireblocks`](crate::GeneralCustody::Fireblocks) requires. A wrong
//! `vault_pubkey` would otherwise send change and payouts to a script that the vault cannot sign
//! for. See that function for the checks.
//!
//! ## Auth
//!
//! Every request carries `X-API-Key: <api key>` and `Authorization: Bearer <JWT>`, where the
//! JWT is RS256-signed with the operator's Fireblocks API secret (an RSA private key) and
//! carries `{ uri, nonce, iat, exp, sub = api key, bodyHash = SHA256(raw body) }`.

mod auth;
mod client;
mod config;
mod dto;
mod errors;
mod raw;
mod sign;
#[cfg(test)]
mod test_utils;
mod vault;

pub use self::{
    client::FireblocksSigner,
    config::FireblocksConfig,
    errors::{FireblocksError, FireblocksInitError, StartupCheckError},
    vault::CheckedVault,
};
