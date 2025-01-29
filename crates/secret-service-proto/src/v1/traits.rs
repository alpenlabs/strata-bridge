use std::future::Future;

use bitcoin::Psbt;
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::PublicKey,
    AggNonce, LiftedSignature, PartialSignature, PubNonce,
};
use quinn::{ConnectionError, ReadExactError, WriteError};
use rkyv::rancor;

use super::wire::ServerMessage;

pub trait SecretServiceFactory<FirstRound, SecondRound>: Send + Clone
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
{
    type Context: Send + Clone;
    type Service: SecretService<Server, FirstRound, SecondRound> + Send;
    fn produce(ctx: Self::Context) -> Self::Service;
}

// possible when https://github.com/rust-lang/rust/issues/63063 is stabliized
// pub type AsyncResult<T, E = ()> = impl Future<Output = Result<T, E>>;

pub trait SecretService<O, FirstRound, SecondRound>: Send
where
    O: Origin,
    FirstRound: Musig2SignerFirstRound<O, SecondRound>,
{
    type OperatorSigner: OperatorSigner<O>;
    type P2PSigner: P2PSigner<O>;
    type Musig2Signer: Musig2Signer<O, FirstRound>;
    type WotsSigner: WotsSigner<O>;

    fn operator_signer(&self) -> Self::OperatorSigner;
    fn p2p_signer(&self) -> Self::P2PSigner;
    fn musig2_signer(&self) -> Self::Musig2Signer;
    fn wots_signer(&self) -> Self::WotsSigner;
}

pub trait OperatorSigner<O: Origin>: Send {
    // type OperatorSigningError: Debug
    //     + Send
    //     + Clone
    //     + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>;

    fn sign_psbt(&self, psbt: Psbt) -> impl Future<Output = O::Container<Psbt>> + Send;
}

pub trait P2PSigner<O: Origin>: Send {
    // type P2PSigningError: Debug
    //     + Send
    //     + Clone
    //     + for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>;

    fn sign_p2p(&self, hash: [u8; 32]) -> impl Future<Output = O::Container<[u8; 64]>> + Send;

    fn p2p_pubkey(&self) -> impl Future<Output = O::Container<[u8; 33]>> + Send;
}

pub type Musig2SessionId = usize;

pub trait Musig2Signer<O: Origin, FirstRound>: Send + Sync {
    fn new_session(&self) -> impl Future<Output = O::Container<FirstRound>> + Send;
}

pub trait Musig2SignerFirstRound<O: Origin, SecondRound>: Send + Sync {
    fn our_nonce(&self) -> impl Future<Output = O::Container<PubNonce>> + Send;

    fn holdouts(&self) -> impl Future<Output = O::Container<Vec<PublicKey>>> + Send;

    fn is_complete(&self) -> impl Future<Output = O::Container<bool>> + Send;

    fn receive_pub_nonce(
        &self,
        pubkey: PublicKey,
        pubnonce: PubNonce,
    ) -> impl Future<Output = O::Container<Result<(), RoundContributionError>>> + Send;

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<Output = O::Container<Result<SecondRound, RoundFinalizeError>>> + Send;
}

pub trait Musig2SignerSecondRound<O: Origin>: Send + Sync {
    fn agg_nonce(&self) -> impl Future<Output = O::Container<AggNonce>> + Send;

    fn holdouts(&self) -> impl Future<Output = O::Container<Vec<PublicKey>>> + Send;

    fn our_signature(&self) -> impl Future<Output = O::Container<PartialSignature>> + Send;

    fn is_complete(&self) -> impl Future<Output = O::Container<bool>> + Send;

    fn receive_signature(
        &self,
        pubkey: PublicKey,
        signature: PartialSignature,
    ) -> impl Future<Output = O::Container<Result<(), RoundContributionError>>> + Send;

    fn finalize(
        self,
    ) -> impl Future<Output = O::Container<Result<LiftedSignature, RoundFinalizeError>>> + Send;
}

pub trait WotsSigner<O: Origin>: Send {
    fn get_key(&self, index: u64) -> impl Future<Output = O::Container<[u8; 64]>> + Send;
}

pub trait Origin {
    type Container<T>;
}

/// Enforcer for other traits to ensure implementations only work for either the client or server
pub struct Server;
impl Origin for Server {
    type Container<T> = T;
}

pub struct Client;
impl Origin for Client {
    type Container<T> = Result<T, ClientError>;
}

pub enum ClientError {
    ConnectionError(ConnectionError),
    SerializationError(rancor::Error),
    DeserializationError(rancor::Error),
    BadData,
    WriteError(WriteError),
    ReadError(ReadExactError),
    Timeout,
    ProtocolError(ServerMessage),
}
