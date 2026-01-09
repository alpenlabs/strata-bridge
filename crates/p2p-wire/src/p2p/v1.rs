//! Strata P2P protocol v1 messages.

#![allow(missing_docs)] // rkyv::Archive introduces a bunch of these errors which we can't control.

use std::fmt;

use bitcoin::hex::DisplayHex;
use libp2p::{
    identity::{ed25519::PublicKey as LibP2pEdPublicKey, PublicKey as LibP2pPublicKey},
    PeerId,
};
use rkyv::{Archive, Deserialize, Serialize};
use strata_bridge_p2p_types::{
    P2POperatorPubKey, PartialSignature, PubNonce, Scope, SessionId, Sha256Hash, StakeChainId,
    Txid, WotsPublicKeys, XOnlyPublicKey,
};

/// Typed version of "get_message_request::GetMessageRequest".
#[derive(Clone, Archive, Serialize, Deserialize)]
pub enum GetMessageRequest {
    /// Request Stake Chain info for this operator.
    StakeChainExchange {
        /// 32-byte hash of some unique to stake chain data.
        stake_chain_id: StakeChainId,

        /// The P2P Operator's public key that the request came from.
        operator_pk: P2POperatorPubKey,
    },

    /// Request deposit setup info for [`Scope`] and operator.
    DepositSetup {
        /// [`Scope`] of the deposit data.
        scope: Scope,

        /// The P2P Operator's public key that the request came from.
        operator_pk: P2POperatorPubKey,
    },

    /// Request MuSig2 (partial) signatures from operator and for [`SessionId`].
    Musig2SignaturesExchange {
        /// [`SessionId`] of either the deposit data or the root deposit data.
        session_id: SessionId,

        /// The P2P Operator's public key that the request came from.
        operator_pk: P2POperatorPubKey,
    },

    /// Request MuSig2 (public) nonces from operator and for [`SessionId`].
    Musig2NoncesExchange {
        /// [`SessionId`] of either the deposit data or the root deposit data.
        session_id: SessionId,

        /// The P2P Operator's public key that the request came from.
        operator_pk: P2POperatorPubKey,
    },
}

impl GetMessageRequest {
    /// Returns the P2P [`P2POperatorPubKey`] with respect to this [`GetMessageRequest`].
    pub const fn operator_pubkey(&self) -> &P2POperatorPubKey {
        match self {
            Self::StakeChainExchange { operator_pk, .. }
            | Self::DepositSetup { operator_pk, .. }
            | Self::Musig2NoncesExchange { operator_pk, .. }
            | Self::Musig2SignaturesExchange { operator_pk, .. } => operator_pk,
        }
    }

    /// Returns the [`PeerId`] with respect to this [`GetMessageRequest`].
    pub fn peer_id(&self) -> PeerId {
        match self {
            Self::StakeChainExchange { operator_pk, .. }
            | Self::DepositSetup { operator_pk, .. }
            | Self::Musig2NoncesExchange { operator_pk, .. }
            | Self::Musig2SignaturesExchange { operator_pk, .. } => {
                // convert P2POperatorPubKey into LibP2P secp256k1 PK
                let pk =
                    LibP2pEdPublicKey::try_from_bytes(operator_pk.as_ref()).expect("infallible");
                let pk: LibP2pPublicKey = pk.into();
                pk.into()
            }
        }
    }
}

impl fmt::Debug for GetMessageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetMessageRequest::StakeChainExchange {
                operator_pk,
                stake_chain_id,
            } => write!(
                f,
                "StakeChainExchange(operator_pk: {operator_pk}, stake_chain_id: {stake_chain_id})"
            ),

            GetMessageRequest::DepositSetup { operator_pk, scope } => write!(
                f,
                "DepositSetup(operator_pk: {operator_pk}, scope: {scope})"
            ),

            GetMessageRequest::Musig2SignaturesExchange {
                operator_pk,
                session_id,
            } => write!(
                f,
                "Musig2SignaturesExchange(operator_pk: {operator_pk}, session_id: {session_id})"
            ),

            GetMessageRequest::Musig2NoncesExchange {
                operator_pk,
                session_id,
            } => write!(
                f,
                "Musig2NoncesExchange(operator_pk: {operator_pk}, session_id: {session_id})"
            ),
        }
    }
}

impl fmt::Display for GetMessageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StakeChainExchange {
                operator_pk,
                stake_chain_id,
            } => write!(
                f,
                "StakeChainExchange(operator_pk: {operator_pk}, stake_chain_id: {stake_chain_id})"
            ),

            Self::DepositSetup { operator_pk, scope } => write!(
                f,
                "DepositSetup(operator_pk: {operator_pk}, scope: {scope})"
            ),

            Self::Musig2NoncesExchange {
                operator_pk,
                session_id,
            } => write!(
                f,
                "Musig2NoncesExchange(operator_pk: {operator_pk}, session_id: {session_id})"
            ),

            Self::Musig2SignaturesExchange {
                operator_pk,
                session_id,
            } => write!(
                f,
                "Musig2SignaturesExchange(operator_pk: {operator_pk}, session_id: {session_id})"
            ),
        }
    }
}

/// New deposit request appeared, and operators exchanging setup data.
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct DepositSetup {
    /// [`Sha256Hash`] hash of the stake transaction that the preimage is revealed when advancing
    /// the stake.
    pub hash: Sha256Hash,

    /// Funding transaction ID.
    ///
    /// Used to cover the dust outputs in the transaction graph connectors.
    pub funding_txid: Txid,

    /// Funding transaction output index.
    ///
    /// Used to cover the dust outputs in the transaction graph connectors.
    pub funding_vout: u32,

    // TODO I'll need to wrap this in a newtype
    /// Operator's X-only public key to construct a P2TR address to reimburse the
    /// operator for a valid withdraw fulfillment.
    // TODO: convert this a BOSD descriptor.
    pub operator_pk: XOnlyPublicKey,

    /// Winternitz One-Time Signature (WOTS) public keys shared in a deposit.
    pub wots_pks: WotsPublicKeys,
}

impl fmt::Debug for DepositSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = self.hash.to_lower_hex_string();
        let funding_txid = self.funding_txid.to_lower_hex_string();
        let funding_vout = self.funding_vout;
        let operator_pk = self.operator_pk.to_lower_hex_string();
        let wots_pks = &self.wots_pks; // not so big because of the custom Debug implementation

        write!(f, "DepositSetup(hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk}, wots_pks: {wots_pks:?})")
    }
}

impl fmt::Display for DepositSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = self.hash.to_lower_hex_string();
        let funding_txid = self.funding_txid.to_lower_hex_string();
        let funding_vout = self.funding_vout;
        let operator_pk = self.operator_pk.to_lower_hex_string();

        write!(f, "DepositSetup(hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk})")
    }
}

/// Info provided during initial startup of nodes.
///
/// This is primarily used for the Stake Chain setup.
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct StakeChainExchange {
    /// [`Txid`] of the pre-stake transaction.
    pub pre_stake_txid: Txid,

    /// vout of the pre-stake transaction.
    pub pre_stake_vout: u32,
}

impl fmt::Debug for StakeChainExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pre_stake_txid = self.pre_stake_txid.to_lower_hex_string();
        let pre_stake_vout = self.pre_stake_vout;
        write!(
            f,
            "StakeChainExchange(pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
        )
    }
}

impl fmt::Display for StakeChainExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pre_stake_txid = self.pre_stake_txid.to_lower_hex_string();
        let pre_stake_vout = self.pre_stake_vout;
        write!(
            f,
            "StakeChainExchange(pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
        )
    }
}

/// Unsigned messages exchanged between operators.
#[derive(Clone, Archive, Serialize, Deserialize)]
#[expect(clippy::large_enum_variant)]
pub enum UnsignedGossipsubMsg {
    /// Operators exchange stake chain info.
    StakeChainExchange {
        /// 32-byte hash of some unique to stake chain data.
        stake_chain_id: StakeChainId,

        // TODO I'll need to wrap this in a newtype
        /// 32-byte x-only public key of the operator used to advance the stake chain.
        operator_pk: XOnlyPublicKey,

        // TODO I'll need to wrap this in a newtype
        /// [`Txid`] of the pre-stake transaction.
        pre_stake_txid: Txid,

        /// vout of the pre-stake transaction.
        pre_stake_vout: u32,
    },

    /// New deposit request appeared, and operators
    /// exchanging setup data.
    ///
    /// This is primarily used for the WOTS PKs.
    DepositSetup {
        /// [`Scope`] of the deposit data.
        scope: Scope,

        /// Index of the deposit.
        index: u32,

        /// [`Sha256Hash`] hash of the stake transaction that the preimage is revealed when
        /// advancing the stake.
        hash: Sha256Hash,

        /// Funding transaction ID.
        ///
        /// Used to cover the dust outputs in the transaction graph connectors.
        funding_txid: Txid,

        /// Funding transaction output index.
        ///
        /// Used to cover the dust outputs in the transaction graph connectors.
        funding_vout: u32,

        /// Operator's X-only public key to construct a P2TR address to reimburse the
        /// operator for a valid withdraw fulfillment.
        // TODO: convert this a BOSD descriptor.
        operator_pk: XOnlyPublicKey,

        /// Winternitz One-Time Signature (WOTS) public keys shared in a deposit.
        wots_pks: WotsPublicKeys,
    },

    /// Operators exchange (public) nonces before signing.
    Musig2NoncesExchange {
        /// [`SessionId`] of either the deposit data or the root deposit data.
        session_id: SessionId,

        /// (Public) Nonces for each transaction.
        nonces: Vec<PubNonce>,
    },

    /// Operators exchange (partial) signatures for the transaction graph.
    Musig2SignaturesExchange {
        /// [`SessionId`] of either the deposit data or the root deposit data.
        session_id: SessionId,

        /// (Partial) Signatures for each transaction.
        signatures: Vec<PartialSignature>,
    },
}

impl UnsignedGossipsubMsg {
    /// Returns content of the message for signing.
    ///
    /// Depending on the variant, concatenates serialized data of the variant and returns it as
    /// a [`Vec`] of bytes.
    pub fn content(&self) -> Vec<u8> {
        let mut content = Vec::new();

        match &self {
            Self::StakeChainExchange {
                stake_chain_id,
                operator_pk,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                content.extend(stake_chain_id.as_ref());
                content.extend(operator_pk.to_bytes());
                content.extend(pre_stake_txid.to_bytes());
                content.extend(pre_stake_vout.to_le_bytes());
            }
            Self::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => {
                content.extend(scope.as_ref());
                content.extend(index.to_le_bytes());
                content.extend(hash.to_bytes());
                content.extend(funding_txid.to_bytes());
                content.extend(funding_vout.to_le_bytes());
                content.extend(operator_pk.to_bytes());
                content.extend(wots_pks.to_flattened_bytes());
            }
            Self::Musig2NoncesExchange { session_id, nonces } => {
                content.extend(session_id.as_ref());
                for nonce in nonces {
                    content.extend(nonce.to_bytes());
                }
            }
            Self::Musig2SignaturesExchange {
                session_id,
                signatures,
            } => {
                content.extend(session_id.as_ref());
                for sig in signatures {
                    content.extend(sig.to_bytes());
                }
            }
        };

        content
    }
}

impl fmt::Debug for UnsignedGossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                operator_pk,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                let operator_pk = operator_pk.to_lower_hex_string();
                let pre_stake_txid = pre_stake_txid.to_lower_hex_string();
                write!(
                    f,
                    "StakeChainExchange(stake_chain_id: {stake_chain_id}, operator_pk: {operator_pk}, pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
                )
            }
            UnsignedGossipsubMsg::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => {
                let hash = hash.to_lower_hex_string();
                let operator_pk = operator_pk.to_lower_hex_string();
                let funding_txid = funding_txid.to_lower_hex_string();
                write!(
                    f,
                    "DepositSetup(scope: {scope}, index: {index}, hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk}, wots_pks: {wots_pks:?})"
                )
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces } => {
                let nonces_count = nonces.len();
                write!(
                    f,
                    "Musig2NoncesExchange(session_id: {session_id}, nonces_count: {nonces_count})"
                )
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                signatures,
            } => {
                let signatures_count = signatures.len();
                write!(
                    f,
                    "Musig2SignaturesExchange(session_id: {session_id}, signatures_count: {signatures_count})"
                )
            }
        }
    }
}

impl fmt::Display for UnsignedGossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                operator_pk,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                let operator_pk = operator_pk.to_lower_hex_string();
                let pre_stake_txid = pre_stake_txid.to_lower_hex_string();
                write!(
                    f,
                    "StakeChainExchange(stake_chain_id: {stake_chain_id}, operator_pk: {operator_pk}, pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
                )
            }
            UnsignedGossipsubMsg::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                ..
            } => {
                let hash = hash.to_lower_hex_string();
                let funding_txid = funding_txid.to_lower_hex_string();
                let operator_pk = operator_pk.to_lower_hex_string();
                write!(
                    f,
                    "DepositSetup(scope: {scope}, index: {index}, hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk})"
                )
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces } => {
                let nonces_count = nonces.len();
                write!(
                    f,
                    "Musig2NoncesExchange(session_id: {session_id}, nonces_count: {nonces_count})"
                )
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                signatures,
            } => {
                let signatures_count = signatures.len();
                write!(
                    f,
                    "Musig2SignaturesExchange(session_id: {session_id}, signatures_count: {signatures_count})"
                )
            }
        }
    }
}

/// Gossipsub message.
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct GossipsubMsg {
    /// Operator's signature of the message.
    pub signature: Vec<u8>,

    /// Operator's P2P public key.
    pub key: P2POperatorPubKey,

    /// Unsigned payload.
    pub unsigned: UnsignedGossipsubMsg,
}

impl GossipsubMsg {
    /// Returns the content of the message as raw bytes.
    pub fn content(&self) -> Vec<u8> {
        self.unsigned.content()
    }
}

impl fmt::Debug for GossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = self.key.to_string();
        let signature = self.signature.to_lower_hex_string();
        let unsigned = &self.unsigned;
        write!(
            f,
            "GossipsubMsg(key: {key}, signature: {signature}, unsigned: {unsigned:?})"
        )
    }
}

impl fmt::Display for GossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = self.key.to_string();
        let signature = self.signature.to_lower_hex_string();
        let unsigned = &self.unsigned;
        write!(
            f,
            "GossipsubMsg(key: {key}, signature: {signature}, unsigned: {unsigned})",
        )
    }
}
