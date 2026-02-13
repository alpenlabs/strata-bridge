//! The traits that make up the secret service's interfaces

use std::future::Future;

use bitcoin::{OutPoint, TapNodeHash, Txid, XOnlyPublicKey};
use bitvm::signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256};
use libp2p_identity::ed25519::SecretKey;
use musig2::{secp256k1::schnorr::Signature, AggNonce, PartialSignature, PubNonce};
use quinn::{ConnectionError, ReadExactError, WriteError};
use rkyv::{rancor, Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootTweak;
use terrors::OneOf;

use super::wire::ServerMessage;

// FIXME: possible when https://github.com/rust-lang/rust/issues/63063 is stabliized
// pub type AsyncResult<T, E = ()> = impl Future<Output = Result<T, E>>;

/// Core interface for the Secret Service, implemented by both the client and the server with
/// different versions.
pub trait SecretService<O>: Send
where
    O: Origin,
{
    /// Implementation of the [`SchnorrSigner`] trait for the general wallet.
    type GeneralWalletSigner: SchnorrSigner<O>;
    /// Implementation of the [`SchnorrSigner`] trait for the stakechain wallet.
    type StakechainWalletSigner: SchnorrSigner<O>;

    /// Implementation of the [`P2PSigner`] trait.
    type P2PSigner: P2PSigner<O>;

    /// Implementation of the [`Musig2Signer`] trait.
    type Musig2Signer: Musig2Signer<O>;

    /// Implementation of the [`WotsSigner`] trait.
    type WotsSigner: WotsSigner<O>;

    /// Implementation of the [`StakeChainPreimages`] trait.
    type StakeChainPreimages: StakeChainPreimages<O>;

    /// The general wallet signer signs transactions for the operator's wallet
    /// for fronting withdrawals, CPFP ops and funding the stakechain wallet
    fn general_wallet_signer(&self) -> Self::GeneralWalletSigner;

    /// The stakechain wallet signer signs transactions for the operator's stakechain wallet
    /// which manages the stake `s` from an operator as well as a smaller set of UTXOs for funding
    /// claim transactions.
    fn stakechain_wallet_signer(&self) -> Self::StakechainWalletSigner;

    /// Creates an instance of the [`P2PSigner`].
    fn p2p_signer(&self) -> Self::P2PSigner;

    /// Creates an instance of the [`Musig2Signer`].
    fn musig2_signer(&self) -> Self::Musig2Signer;

    /// Creates an instance of the [`WotsSigner`].
    fn wots_signer(&self) -> Self::WotsSigner;

    /// Creates an instance of the [`StakeChainPreimages`].
    fn stake_chain_preimages(&self) -> Self::StakeChainPreimages;
}

/// Wallet signers sign transactions for one of the operator's wallets
///
/// # Warning
///
/// The user should make sure the operator's secret key should have its own unique key that isn't
/// used for any other purpose.
pub trait SchnorrSigner<O: Origin>: Send {
    /// Signs a `digest` using the operator's [`SecretKey`].
    fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> impl Future<Output = O::Container<Signature>> + Send;

    /// Signs a digest using the operator's [`SecretKey`] assuming that the tweak is not necessary.
    ///
    /// A common use case is when the key is part of a taproot script (i.e., in a script path
    /// spend).
    fn sign_no_tweak(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = O::Container<Signature>> + Send;

    /// Returns the public key of the operator's secret key.
    fn pubkey(&self) -> impl Future<Output = O::Container<XOnlyPublicKey>> + Send;
}

/// The P2P signer is used for signing messages between operators on the peer-to-peer network.
///
/// # Warning
///
/// The user should make sure the operator's secret key should have its own unique key that isn't
/// used for any other purpose.
pub trait P2PSigner<O: Origin>: Send {
    /// Returns the [`SecretKey`] that should be used for signing P2P messages
    fn secret_key(&self) -> impl Future<Output = O::Container<SecretKey>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct OurPubKeyIsNotInParams;

/// We could not verify the signature we produced.
/// This may indicate a malicious actor attempted to make us
/// produce a signature which could reveal our secret key. The
/// signing session should be aborted and retried with new nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct SelfVerifyFailed;

/// The final signature is not valid for the given key and message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct BadFinalSignature;

/// This error is returned by when a peer provides an invalid contribution
/// to one of the signing rounds.
///
/// This is either because the signer's index exceeds the maximum, or
/// because we received an invalid contribution from this signer.
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
pub struct RoundContributionError {
    /// The erroneous signer index.
    pub index: usize,
    /// The reason why the signer's contribution was rejected.
    pub reason: ContributionFaultReason,
}

impl From<musig2::errors::RoundContributionError> for RoundContributionError {
    fn from(value: musig2::errors::RoundContributionError) -> Self {
        Self {
            index: value.index,
            reason: value.reason.into(),
        }
    }
}

impl From<RoundContributionError> for musig2::errors::RoundContributionError {
    fn from(val: RoundContributionError) -> Self {
        musig2::errors::RoundContributionError {
            index: val.index,
            reason: val.reason.into(),
        }
    }
}

/// Enumerates the causes for why receiving a contribution from a peer
/// might fail.
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
pub enum ContributionFaultReason {
    /// The signer's index is out of range for the given
    /// number of signers in the group. Embeds `n_signers`
    /// (the number of signers).
    OutOfRange(usize),

    /// Indicates we received different contribution values from
    /// this peer for the same round. If we receive the same
    /// nonce or signature from this peer more than once this is
    /// acceptable and treated as a no-op, but receiving inconsistent
    /// contributions from the same signer may indicate there is
    /// malicious behavior occurring.
    InconsistentContribution,

    /// Indicates we received an invalid partial signature.
    InvalidSignature,
}

impl From<musig2::errors::ContributionFaultReason> for ContributionFaultReason {
    fn from(value: musig2::errors::ContributionFaultReason) -> Self {
        match value {
            musig2::errors::ContributionFaultReason::OutOfRange(v) => Self::OutOfRange(v),
            musig2::errors::ContributionFaultReason::InconsistentContribution => {
                Self::InconsistentContribution
            }
            musig2::errors::ContributionFaultReason::InvalidSignature => Self::InvalidSignature,
        }
    }
}

impl From<ContributionFaultReason> for musig2::errors::ContributionFaultReason {
    fn from(val: ContributionFaultReason) -> Self {
        match val {
            ContributionFaultReason::OutOfRange(v) => {
                musig2::errors::ContributionFaultReason::OutOfRange(v)
            }
            ContributionFaultReason::InconsistentContribution => {
                musig2::errors::ContributionFaultReason::InconsistentContribution
            }
            ContributionFaultReason::InvalidSignature => {
                musig2::errors::ContributionFaultReason::InvalidSignature
            }
        }
    }
}

/// The MuSig2 signer trait is used by the caller to request the operations
/// requiring knowledge of secrets which only S2 possesses. This API was
/// redesigned to be fully idempotent and deterministic, and doesn't hold any
/// state on S2 outside of the statically configured keys.
///
/// # Warning
///
/// A single secret key should be used across all sessions initiated by this signer,
/// whose public key should be accessible via the [`SchnorrSigner::pubkey`] method.
pub trait Musig2Signer<O: Origin>: SchnorrSigner<O> + Send + Sync {
    /// Given the params of a musig2 session, deterministically generate a
    /// public nonce. S2 will create a secret nonce deterministically, then
    /// derive the public nonce from it and return it to the caller.
    fn get_pub_nonce(
        &self,
        params: Musig2Params,
    ) -> impl Future<Output = O::Container<Result<PubNonce, OurPubKeyIsNotInParams>>> + Send;

    /// Given the params of a musig2 session, an aggregated nonce created from
    /// the signers' session pubnonces and the message to sign, return a partial
    /// signature. These can be validated and aggregated into the final
    /// signature valid for the musig2 group public key by the caller.
    ///
    /// Fails if our pubkey wasn't present in [`Musig2Params::ordered_pubkeys`],
    /// or if the signature we produced fails to verify.
    fn get_our_partial_sig(
        &self,
        params: Musig2Params,
        aggnonce: AggNonce,
        message: [u8; 32],
    ) -> impl Future<
        Output = O::Container<
            Result<PartialSignature, OneOf<(OurPubKeyIsNotInParams, SelfVerifyFailed)>>,
        >,
    > + Send;
}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Musig2Params {
    pub ordered_pubkeys: Vec<XOnlyPublicKey>,
    pub tweak: TaprootTweak,
    /// The inpoint of a transaction being signed.
    ///
    /// This is composed of the [`Txid`] of the transaction being signed and its input index
    /// (`vout`).
    pub input: OutPoint,
}

/// Winternitz One-Time Signatures (WOTS) are used to transfer state across UTXOs, even though
/// bitcoin does not support this natively.
///
/// This signer returns deterministic keys so the caller can assemble a transaction.
pub trait WotsSigner<O: Origin>: Send {
    /// Returns a deterministic WOTS secret key for a given transaction ID, vout,
    /// and WOTS index. The secret key can be obtained via [`Self::get_128_secret_key`] with the
    /// same arguments.
    fn get_128_secret_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 36]>> + Send;

    /// Returns a deterministic WOTS secret key for a given transaction ID, vout,
    /// and WOTS index. The public key can be obtained via [`Self::get_256_public_key`] with the
    /// same arguments.
    fn get_256_secret_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 68]>> + Send;

    /// Returns a deterministic WOTS public key for a given transaction ID, vout,
    /// and WOTS index. The secret key can be obtained via [`Self::get_128_secret_key`] with the
    /// same arguments.
    fn get_128_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 36]>> + Send;

    /// Returns a deterministic public key for a given transaction ID, vout,
    /// and WOTS index. The secret key can be obtained via [`Self::get_256_secret_key`] with the
    /// same parameters.
    fn get_256_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 68]>> + Send;

    fn get_128_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 16],
    ) -> impl Future<Output = O::Container<<wots_hash as Wots>::Signature>> + Send;

    fn get_256_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 32],
    ) -> impl Future<Output = O::Container<<wots256 as Wots>::Signature>> + Send;
}

/// The Stake Chain preimages are used to generate deterministic preimages for the Stake Chain
/// used to advance the operator's stake while fulfilling withdrawals.
pub trait StakeChainPreimages<O: Origin>: Send {
    /// Returns a deterministic preimage for a given stakechain withdrawal through a given pre-stake
    /// txid, and vout; and stake index.
    fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> impl Future<Output = O::Container<[u8; 32]>> + Send;
}

/// Parameterizes the main secret service traits so that clients and servers alike can implement a
/// single trait, but clients will receive the server's response wrapped in a result with other
/// spurious network or protocol errors it may encounter.
pub trait Origin {
    /// Container type for responses from secret service traits.
    type Container<T>;
}

/// Enforcer for other traits to ensure implementations only work for the server & provides
/// container type
#[derive(Debug)]
pub struct Server;
impl Origin for Server {
    // for the server, this is just a transparent wrapper
    type Container<T> = T;
}

/// Enforcer for other traits to ensure implementations only work for the client and provides
/// container type.
#[derive(Debug, Clone)]
pub struct Client;
impl Origin for Client {
    // For the client, the server wrap responses in a result that may have a client error.
    type Container<T> = Result<T, ClientError>;
}

/// Various errors a client may encounter when interacting with the Secret Service.
#[derive(Debug)]
pub enum ClientError {
    /// Connection was lost or had an error.
    ConnectionError(ConnectionError),

    /// Unusual: `rkyv` failed to serialize something. Indicates something very bad has happened.
    SerializationError(rancor::Error),

    /// `rkyv` failed to deserialize something. Something's probably weird on the
    /// server side.
    DeserializationError(rancor::Error),

    /// Failed to deserialize something. Server is giving us bad responses.
    BadData,

    /// Failed to write data towards the server.
    WriteError(WriteError),

    /// Failed to read data from the server.
    ReadError(ReadExactError),

    /// The server took too long to respond.
    Timeout,

    /// We ran out of retries
    NoMoreRetries,

    /// The server sent a message that was not expected.
    WrongMessage(Box<ServerMessage>),

    /// The server sent a message with an unexpected protocol version.
    WrongVersion,
}

impl std::error::Error for ClientError {}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:?}"))
    }
}
