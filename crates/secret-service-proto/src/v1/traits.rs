//! The traits that make up the secret service's interfaces

use std::future::Future;

use bitcoin::{Txid, XOnlyPublicKey};
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{schnorr::Signature, SecretKey},
    AggNonce, LiftedSignature, PartialSignature, PubNonce,
};
use quinn::{ConnectionError, ReadExactError, WriteError};
use rkyv::{rancor, Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use super::wire::ServerMessage;

// FIXME: possible when https://github.com/rust-lang/rust/issues/63063 is stabliized
// pub type AsyncResult<T, E = ()> = impl Future<Output = Result<T, E>>;

/// Core interface for the Secret Service, implemented by both the client and the server with
/// different versions.
pub trait SecretService<O, FirstRound, SecondRound>: Send
where
    O: Origin,
    FirstRound: Musig2SignerFirstRound<O, SecondRound>,
{
    /// Implementation of the [`OperatorSigner`] trait.
    type OperatorSigner: OperatorSigner<O>;

    /// Implementation of the [`P2PSigner`] trait.
    type P2PSigner: P2PSigner<O>;

    /// Implementation of the [`Musig2Signer`] trait.
    type Musig2Signer: Musig2Signer<O, FirstRound>;

    /// Implementation of the [`WotsSigner`] trait.
    type WotsSigner: WotsSigner<O>;

    /// Implementation of the [`StakeChainPreimages`] trait.
    type StakeChainPreimages: StakeChainPreimages<O>;

    /// Creates an instance of the [`OperatorSigner`].
    fn operator_signer(&self) -> Self::OperatorSigner;

    /// Creates an instance of the [`P2PSigner`].
    fn p2p_signer(&self) -> Self::P2PSigner;

    /// Creates an instance of the [`Musig2Signer`].
    fn musig2_signer(&self) -> Self::Musig2Signer;

    /// Creates an instance of the [`WotsSigner`].
    fn wots_signer(&self) -> Self::WotsSigner;

    /// Creates an instance of the [`StakeChainPreimages`].
    fn stake_chain_preimages(&self) -> Self::StakeChainPreimages;
}

/// The operator signer signs transactions for the operator's own wallet that
/// is used for fronting withdrawals and other operations.
///
/// # Warning
///
/// The user should make sure the operator's secret key should have its own unique key that isn't
/// used for any other purpose.
pub trait OperatorSigner<O: Origin>: Send {
    /// Signs a `digest` using the operator's [`SecretKey`](bitcoin::secp256k1::SecretKey).
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = O::Container<Signature>> + Send;

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

/// Uniquely identifies an in-memory MuSig2 session on the signing server.
pub type Musig2SessionId = usize;

/// Error returned when trying to access a signer that is out of bounds.
#[derive(Debug, Archive, Serialize, Deserialize, Clone)]
pub struct SignerIdxOutOfBounds {
    /// Index tried to access.
    pub index: usize,

    /// Number of signers in the session.
    pub n_signers: usize,
}

/// The MuSig2 signer trait is used to bootstrap and initialize a MuSig2 session.
///
/// # Warning
///
/// A single secret key should be used across all sessions initiated by this signer,
/// whose public key should be accessible via the [`Musig2Signer::pubkey`] method.
pub trait Musig2Signer<O: Origin, FirstRound>: Send + Sync {
    /// Initializes a new MuSig2 session with the given public keys, witness, input transaction ID,
    /// and input vout.
    ///
    /// # Warning
    ///
    /// `pubkeys` may or may not include our own pubkey and should be added if not
    /// included by implementer. `pubkeys` may or may not be sorted, so should be sorted
    /// deterministically (after addition of our own pubkey if required) before session creation.
    fn new_session(
        &self,
        pubkeys: Vec<XOnlyPublicKey>,
        witness: TaprootWitness,
        input_txid: Txid,
        input_vout: u32,
    ) -> impl Future<Output = O::Container<Result<FirstRound, SignerIdxOutOfBounds>>> + Send;

    /// Retrieves the public key associated with this MuSig2 signer.
    fn pubkey(&self) -> impl Future<Output = O::Container<XOnlyPublicKey>> + Send;
}

/// Represents a state-machine-like API for performing MuSig2 signing.
///
/// This first round is returned by the [`Musig2Signer::new_session`] method of the [`Musig2Signer`]
/// trait.
///
/// # Implementation Details
///
/// This enables ergonomic usage of the (relatively) complex MuSig2 signing process via generics.
/// The `secret-service-client` crate provides a client-side implementation of this trait, and
/// implementers should provide their own implementation server-side.
pub trait Musig2SignerFirstRound<O: Origin, SecondRound>: Send + Sync {
    /// Returns the client's public nonce which should be shared with other signers.
    fn our_nonce(&self) -> impl Future<Output = O::Container<PubNonce>> + Send;

    /// Returns a vector of all signer public keys who the client have yet to receive a [`PubNonce`]
    /// from.
    ///
    /// Note that this will never return our own public key.
    fn holdouts(&self) -> impl Future<Output = O::Container<Vec<XOnlyPublicKey>>> + Send;

    /// Returns `true` once all public nonces have been received from every signer.
    fn is_complete(&self) -> impl Future<Output = O::Container<bool>> + Send;

    /// Adds a [`PubNonce`] to the internal state, registering it to a specific signer at a given
    /// index.
    ///
    /// Returns an error if the signer index is out of range, or if the client already have a
    /// different nonce on-file for that signer.
    fn receive_pub_nonce(
        &mut self,
        pubkey: XOnlyPublicKey,
        pubnonce: PubNonce,
    ) -> impl Future<Output = O::Container<Result<(), RoundContributionError>>> + Send;

    /// Finishes the first round once all nonces are received, combining nonces
    /// into an aggregated nonce, and creating a partial signature using `seckey`
    /// on a given `message`, both of which are stored in the returned `SecondRound`.
    ///
    /// This method intentionally consumes the `FirstRound`, to avoid accidentally
    /// reusing a secret-nonce.
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signing fails, probably because the wrong secret key was given.
    ///
    /// For all partial signatures to be valid, everyone must naturally be signing the
    /// same message.
    fn finalize(
        self,
        digest: [u8; 32],
    ) -> impl Future<Output = O::Container<Result<SecondRound, RoundFinalizeError>>> + Send;
}

/// This trait represents the second round of the MuSig2 signing process.
/// It is responsible for aggregating the partial signatures into a single
/// signature, and for verifying the aggregated signature.
pub trait Musig2SignerSecondRound<O: Origin>: Send + Sync {
    /// Returns the aggregated nonce built from the nonces provided in the first round. Signers who
    /// find themselves in an aggregator role can distribute this aggregated nonce to other signers
    /// to that they can produce an aggregated signature without 1:1 communication between every
    /// pair of signers.
    fn agg_nonce(&self) -> impl Future<Output = O::Container<AggNonce>> + Send;

    /// Returns a vector of signer public keys from whom the server have yet to receive a
    /// [`PartialSignature`]. Note that since our signature was constructed at the end of the
    /// first round, this vector will never contain our own public key.
    fn holdouts(&self) -> impl Future<Output = O::Container<Vec<XOnlyPublicKey>>> + Send;

    /// Returns the partial signature created during finalization of the first round.
    fn our_signature(&self) -> impl Future<Output = O::Container<PartialSignature>> + Send;

    /// Returns true once the server have all partial signatures from the group.
    fn is_complete(&self) -> impl Future<Output = O::Container<bool>> + Send;

    /// Adds a [`PartialSignature`] to the internal state, registering it to a specific signer.
    /// Returns an error if the signature is not valid, or if the given public key isn't part of
    /// the set of signers, or if the server already have a different partial signature on-file for
    /// that signer.
    fn receive_signature(
        &mut self,
        pubkey: XOnlyPublicKey,
        signature: PartialSignature,
    ) -> impl Future<Output = O::Container<Result<(), RoundContributionError>>> + Send;

    /// Finishes the second round once all partial signatures are received,
    /// combining signatures into an aggregated signature on the `message`
    /// given in the first round finalization.
    ///
    /// # Warning
    ///
    /// This method should only be invoked once
    /// [`is_complete`][Musig2SignerSecondRound::is_complete] returns true, otherwise it will
    /// fail.
    ///
    /// Can also return an error if partial signature aggregation fails, but if
    /// [`receive_signature`][Musig2SignerSecondRound::receive_signature] was successful, then
    /// finalizing will succeed with overwhelming probability.
    fn finalize(
        self,
    ) -> impl Future<Output = O::Container<Result<LiftedSignature, RoundFinalizeError>>> + Send;
}

/// Winternitz One-Time Signatures (WOTS) are used to transfer state across UTXOs, even though
/// bitcoin does not support this natively.
///
/// This signer returns deterministic keys so the caller can assemble a transaction.
pub trait WotsSigner<O: Origin>: Send {
    /// Returns a deterministic key usable for signing 160 bits of data, with 20 bytes per bit;
    /// given a transaction ID, vout, and WOTS index.
    fn get_160_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 160]>> + Send;

    /// Returns a key usable for signing 256 bits of data, with 20 bytes per bit;
    /// given a transaction ID, vout, and WOTS index.
    fn get_256_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = O::Container<[u8; 20 * 256]>> + Send;
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

    /// The server sent a message that was not expected.
    WrongMessage(Box<ServerMessage>),

    /// The server sent a message with an unexpected protocol version.
    WrongVersion,
}
