use std::future::Future;

use bitcoin::Txid;
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{schnorr::Signature, PublicKey},
    AggNonce, LiftedSignature, PartialSignature, PubNonce,
};
use quinn::{ConnectionError, ReadExactError, WriteError};
use rkyv::{rancor, Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use super::wire::ServerMessage;

// possible when https://github.com/rust-lang/rust/issues/63063 is stabliized
// pub type AsyncResult<T, E = ()> = impl Future<Output = Result<T, E>>;

/// The SecretService trait is the core interface for the Secret Service,
/// implemented by both the client and the server with different versions.
pub trait SecretService<O, FirstRound, SecondRound>: Send
where
    O: Origin,
    FirstRound: Musig2SignerFirstRound<O, SecondRound>,
{
    type OperatorSigner: OperatorSigner<O>;
    type P2PSigner: P2PSigner<O>;
    type Musig2Signer: Musig2Signer<O, FirstRound>;
    type WotsSigner: WotsSigner<O>;
    type StakeChainPreimages: StakeChainPreimages<O>;

    fn operator_signer(&self) -> Self::OperatorSigner;
    fn p2p_signer(&self) -> Self::P2PSigner;
    fn musig2_signer(&self) -> Self::Musig2Signer;
    fn wots_signer(&self) -> Self::WotsSigner;
    fn stake_chain_preimages(&self) -> Self::StakeChainPreimages;
}

pub trait OperatorSigner<O: Origin>: Send {
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = O::Container<Signature>> + Send;
    fn pubkey(&self) -> impl Future<Output = O::Container<PublicKey>> + Send;
}

pub trait P2PSigner<O: Origin>: Send {
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = O::Container<Signature>> + Send;
    fn pubkey(&self) -> impl Future<Output = O::Container<PublicKey>> + Send;
}

pub type Musig2SessionId = usize;

#[derive(Debug, Archive, Serialize, Deserialize, Clone)]
pub struct SignerIdxOutOfBounds {
    pub index: usize,
    pub n_signers: usize,
}

pub trait Musig2Signer<O: Origin, FirstRound>: Send + Sync {
    fn new_session(
        &self,
        pubkeys: Vec<PublicKey>,
        witness: TaprootWitness,
        input_txid: Txid,
        input_vout: u32,
    ) -> impl Future<Output = O::Container<Result<FirstRound, SignerIdxOutOfBounds>>> + Send;
    fn pubkey(&self) -> impl Future<Output = O::Container<PublicKey>> + Send;
}

pub trait Musig2SignerFirstRound<O: Origin, SecondRound>: Send + Sync {
    fn our_nonce(&self) -> impl Future<Output = O::Container<PubNonce>> + Send;

    fn holdouts(&self) -> impl Future<Output = O::Container<Vec<PublicKey>>> + Send;

    fn is_complete(&self) -> impl Future<Output = O::Container<bool>> + Send;

    fn receive_pub_nonce(
        &mut self,
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
        &mut self,
        pubkey: PublicKey,
        signature: PartialSignature,
    ) -> impl Future<Output = O::Container<Result<(), RoundContributionError>>> + Send;

    fn finalize(
        self,
    ) -> impl Future<Output = O::Container<Result<LiftedSignature, RoundFinalizeError>>> + Send;
}

pub trait WotsSigner<O: Origin>: Send {
    fn get_160_key(
        &self,
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = O::Container<[u8; 20 * 160]>> + Send;

    fn get_256_key(
        &self,
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = O::Container<[u8; 20 * 256]>> + Send;
}

pub trait StakeChainPreimages<O: Origin>: Send {
    fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> impl Future<Output = O::Container<[u8; 32]>> + Send;
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
    WrongVersion,
}
