//! Types derived from the `.proto` files.

use std::fmt;

use bitcoin::{
    consensus,
    hashes::{sha256, Hash},
    hex::DisplayHex,
    Txid, XOnlyPublicKey,
};
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecp256k1PublicKey, PublicKey as LibP2pPublicKey},
    PeerId,
};
use musig2::{PartialSignature, PubNonce};
use p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use prost::{DecodeError, Message};

use super::proto::{
    get_message_request::Body as ProtoGetMessageRequestBody,
    gossipsub_msg::Body as ProtoGossipsubMsgBody, DepositRequestKey,
    DepositSetupExchange as ProtoDepositSetup, GetMessageRequest as ProtoGetMessageRequest,
    GossipsubMsg as ProtoGossipMsg, Musig2NoncesExchange as ProtoMusig2NoncesExchange,
    Musig2RequestKey, Musig2SignaturesExchange as ProtoMusig2SignaturesExchange,
    StakeChainExchange as ProtoStakeChainExchange, StakeChainRequestKey,
};

/// Typed version of "get_message_request::GetMessageRequest".
#[derive(Clone)]
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
    /// Converts [`ProtoGetMessageRequest`] into [`GetMessageRequest`]
    /// by parsing raw vec values into specific types.
    pub fn from_msg(msg: ProtoGetMessageRequest) -> Result<GetMessageRequest, DecodeError> {
        let body = msg.body.ok_or(DecodeError::new("Message without body"))?;

        let request = match body {
            ProtoGetMessageRequestBody::DepositSetup(DepositRequestKey { scope, operator }) => {
                let bytes = scope
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes in scope"))?;
                let scope = Scope::from_bytes(bytes);

                Self::DepositSetup {
                    scope,
                    operator_pk: operator.into(),
                }
            }
            ProtoGetMessageRequestBody::Nonces(Musig2RequestKey {
                session_id,
                operator,
            }) => {
                let bytes = session_id
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes in session id"))?;
                let session_id = SessionId::from_bytes(bytes);

                Self::Musig2NoncesExchange {
                    session_id,
                    operator_pk: operator.into(),
                }
            }
            ProtoGetMessageRequestBody::Sigs(Musig2RequestKey {
                session_id,
                operator,
            }) => {
                let bytes = session_id
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes in session id"))?;
                let session_id = SessionId::from_bytes(bytes);

                Self::Musig2SignaturesExchange {
                    session_id,
                    operator_pk: operator.into(),
                }
            }
            ProtoGetMessageRequestBody::StakeChain(StakeChainRequestKey {
                stake_chain_id,
                operator,
            }) => {
                let bytes = stake_chain_id
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes in stake chain id"))?;
                let stake_chain_id = StakeChainId::from_bytes(bytes);
                Self::StakeChainExchange {
                    stake_chain_id,
                    operator_pk: operator.into(),
                }
            }
        };

        Ok(request)
    }

    /// Converts [`GetMessageRequest`] into raw [`ProtoGetMessageRequest`].
    pub fn into_msg(self) -> ProtoGetMessageRequest {
        let body = match self {
            Self::StakeChainExchange {
                stake_chain_id,
                operator_pk,
            } => ProtoGetMessageRequestBody::StakeChain(StakeChainRequestKey {
                stake_chain_id: stake_chain_id.to_vec(),
                operator: operator_pk.into(),
            }),
            Self::DepositSetup { scope, operator_pk } => {
                ProtoGetMessageRequestBody::DepositSetup(DepositRequestKey {
                    scope: scope.to_vec(),
                    operator: operator_pk.into(),
                })
            }
            Self::Musig2SignaturesExchange {
                session_id,
                operator_pk,
            } => ProtoGetMessageRequestBody::Sigs(Musig2RequestKey {
                session_id: session_id.to_vec(),
                operator: operator_pk.into(),
            }),
            Self::Musig2NoncesExchange {
                session_id,
                operator_pk,
            } => ProtoGetMessageRequestBody::Nonces(Musig2RequestKey {
                session_id: session_id.to_vec(),
                operator: operator_pk.into(),
            }),
        };

        ProtoGetMessageRequest { body: Some(body) }
    }

    /// Returns the P2P [`P2POperatorPubKey`] with respect to this [`GetMessageRequest`].
    pub fn operator_pubkey(&self) -> &P2POperatorPubKey {
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
                let pk = LibP2pSecp256k1PublicKey::try_from_bytes(operator_pk.as_ref())
                    .expect("infallible");
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
#[derive(Clone)]
pub struct DepositSetup {
    /// [`sha256::Hash`] hash of the stake transaction that the preimage is revealed when advancing
    /// the stake.
    pub hash: sha256::Hash,

    /// Funding transaction ID.
    ///
    /// Used to cover the dust outputs in the transaction graph connectors.
    pub funding_txid: Txid,

    /// Funding transaction output index.
    ///
    /// Used to cover the dust outputs in the transaction graph connectors.
    pub funding_vout: u32,

    /// Operator's X-only public key to construct a P2TR address to reimburse the
    /// operator for a valid withdraw fulfillment.
    // TODO: convert this a BOSD descriptor.
    pub operator_pk: XOnlyPublicKey,

    /// Winternitz One-Time Signature (WOTS) public keys shared in a deposit.
    pub wots_pks: WotsPublicKeys,
}

impl DepositSetup {
    /// Tries to convert a [`ProtoDepositSetup`] into [`DepositSetup`].
    pub fn from_proto_msg(proto: &ProtoDepositSetup) -> Result<Self, DecodeError> {
        let hash = sha256::Hash::from_slice(&proto.hash)
            .map_err(|_| DecodeError::new("invalid length of bytes for hash"))?;
        let funding_txid = consensus::deserialize(&proto.funding_txid)
            .map_err(|_| DecodeError::new("invalid length of bytes for funding txid"))?;
        let funding_vout = proto.funding_vout;
        let operator_pk = XOnlyPublicKey::from_slice(&proto.operator_pk)
            .map_err(|_| DecodeError::new("invalid length of bytes for operator public key"))?;
        let wots_pks = WotsPublicKeys::from_flattened_bytes(&proto.wots_pks);

        Ok(Self {
            hash,
            funding_txid,
            funding_vout,
            operator_pk,
            wots_pks,
        })
    }
}

impl fmt::Debug for DepositSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = self.hash.as_byte_array().to_lower_hex_string();
        let funding_txid = self.funding_txid;
        let funding_vout = self.funding_vout;
        let operator_pk = self.operator_pk.serialize().to_lower_hex_string();
        let wots_pks = &self.wots_pks; // not so big because of the custom Debug implementation

        write!(f, "DepositSetup(hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk}, wots_pks: {wots_pks:?})")
    }
}

impl fmt::Display for DepositSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = self.hash.as_byte_array().to_lower_hex_string();
        let funding_txid = self.funding_txid;
        let funding_vout = self.funding_vout;
        let operator_pk = self.operator_pk.serialize().to_lower_hex_string();

        write!(f, "DepositSetup(hash: {hash}, funding_outpoint: {funding_txid}:{funding_vout}, operator_pk: {operator_pk})")
    }
}

/// Info provided during initial startup of nodes.
///
/// This is primarily used for the Stake Chain setup.
#[derive(Clone)]
pub struct StakeChainExchange {
    /// [`Txid`] of the pre-stake transaction.
    pub pre_stake_txid: Txid,

    /// vout of the pre-stake transaction.
    pub pre_stake_vout: u32,
}

impl StakeChainExchange {
    /// Tries to convert a [`ProtoStakeChainExchange`] into [`StakeChainExchange`].
    pub fn from_proto_msg(proto: &ProtoStakeChainExchange) -> Result<Self, DecodeError> {
        let txid = consensus::deserialize(&proto.pre_stake_txid)
            .map_err(|err| DecodeError::new(err.to_string()))?;

        Ok(Self {
            pre_stake_txid: txid,
            pre_stake_vout: proto.pre_stake_vout,
        })
    }
}

impl fmt::Debug for StakeChainExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pre_stake_txid = self.pre_stake_txid;
        let pre_stake_vout = self.pre_stake_vout;
        write!(
            f,
            "StakeChainExchange(pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
        )
    }
}

impl fmt::Display for StakeChainExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pre_stake_txid = self.pre_stake_txid;
        let pre_stake_vout = self.pre_stake_vout;
        write!(
            f,
            "StakeChainExchange(pre_stake_outpoint: {pre_stake_txid}:{pre_stake_vout})"
        )
    }
}

/// Unsigned messages exchanged between operators.
#[derive(Clone)]
#[expect(clippy::large_enum_variant)]
pub enum UnsignedGossipsubMsg {
    /// Operators exchange stake chain info.
    StakeChainExchange {
        /// 32-byte hash of some unique to stake chain data.
        stake_chain_id: StakeChainId,

        /// 32-byte x-only public key of the operator used to advance the stake chain.
        operator_pk: XOnlyPublicKey,

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

        /// [`sha256::Hash`] hash of the stake transaction that the preimage is revealed when
        /// advancing the stake.
        hash: sha256::Hash,

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
    /// Tries to convert [`ProtoGossipsubMsgBody`] into typed [`UnsignedGossipsubMsg`]
    /// with specific types instead of raw vectors.
    pub fn from_msg_proto(proto: &ProtoGossipsubMsgBody) -> Result<Self, DecodeError> {
        let unsigned = match proto {
            ProtoGossipsubMsgBody::StakeChain(proto) => {
                let bytes =
                    proto.stake_chain_id.as_slice().try_into().map_err(|_| {
                        DecodeError::new("invalid length of bytes for stake chain id")
                    })?;
                let stake_chain_id = StakeChainId::from_bytes(bytes);
                let operator_pk = XOnlyPublicKey::from_slice(&proto.operator_pk)
                    .map_err(|_| DecodeError::new("invalid length of bytes for operator pk"))?;
                let pre_stake_txid = consensus::deserialize(&proto.pre_stake_txid)
                    .map_err(|_| DecodeError::new("invalid length of bytes for pre-stake txid"))?;
                let pre_stake_vout = proto.pre_stake_vout;
                Self::StakeChainExchange {
                    stake_chain_id,
                    operator_pk,
                    pre_stake_txid,
                    pre_stake_vout,
                }
            }
            ProtoGossipsubMsgBody::Setup(proto) => {
                let bytes = proto
                    .scope
                    .as_slice()
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes for scope"))?;
                let scope = Scope::from_bytes(bytes);
                let index = proto.index;
                let hash = sha256::Hash::from_slice(&proto.hash)
                    .map_err(|_| DecodeError::new("invalid length of bytes for hash"))?;
                let funding_txid = consensus::deserialize(&proto.funding_txid)
                    .map_err(|_| DecodeError::new("invalid funding txid"))?;
                let funding_vout = proto.funding_vout;
                let operator_pk = XOnlyPublicKey::from_slice(&proto.operator_pk)
                    .map_err(|_| DecodeError::new("invalid length of bytes for operator pk"))?;
                let wots_pks = WotsPublicKeys::from_flattened_bytes(&proto.wots_pks);

                Self::DepositSetup {
                    scope,
                    index,
                    hash,
                    funding_txid,
                    funding_vout,
                    operator_pk,
                    wots_pks,
                }
            }
            ProtoGossipsubMsgBody::Nonce(proto) => {
                let bytes = proto
                    .session_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes for session id"))?;
                let session_id = SessionId::from_bytes(bytes);

                let nonces = proto
                    .pub_nonces
                    .iter()
                    .map(|bytes| PubNonce::from_bytes(bytes))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| DecodeError::new(err.to_string()))?;

                Self::Musig2NoncesExchange { session_id, nonces }
            }
            ProtoGossipsubMsgBody::Sigs(proto) => {
                let bytes = proto
                    .session_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| DecodeError::new("invalid length of bytes for session id"))?;
                let session_id = SessionId::from_bytes(bytes);

                let partial_sigs = proto
                    .partial_sigs
                    .iter()
                    .map(|bytes| PartialSignature::from_slice(bytes))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| DecodeError::new(err.to_string()))?;

                Self::Musig2SignaturesExchange {
                    session_id,
                    signatures: partial_sigs,
                }
            }
        };

        Ok(unsigned)
    }

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
                content.extend(operator_pk.serialize());
                content.extend(pre_stake_txid.as_byte_array());
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
                content.extend(hash.as_byte_array());
                content.extend(funding_txid.as_byte_array());
                content.extend(funding_vout.to_le_bytes());
                content.extend(operator_pk.serialize());
                content.extend(wots_pks.to_flattened_bytes());
            }
            Self::Musig2NoncesExchange { session_id, nonces } => {
                content.extend(session_id.as_ref());
                for nonce in nonces {
                    content.extend(nonce.serialize());
                }
            }
            Self::Musig2SignaturesExchange {
                session_id,
                signatures,
            } => {
                content.extend(session_id.as_ref());
                for sig in signatures {
                    content.extend(sig.serialize());
                }
            }
        };

        content
    }

    /// Helper function to convert [`UnsignedGossipsubMsg`] into raw [`ProtoGossipsubMsgBody`].
    fn to_raw(&self) -> ProtoGossipsubMsgBody {
        match self {
            Self::StakeChainExchange {
                stake_chain_id,
                operator_pk,
                pre_stake_txid,
                pre_stake_vout,
            } => ProtoGossipsubMsgBody::StakeChain(ProtoStakeChainExchange {
                stake_chain_id: stake_chain_id.to_vec(),
                operator_pk: operator_pk.serialize().to_vec(),
                pre_stake_txid: pre_stake_txid.to_byte_array().to_vec(),
                pre_stake_vout: *pre_stake_vout,
            }),
            Self::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => ProtoGossipsubMsgBody::Setup(ProtoDepositSetup {
                scope: scope.to_vec(),
                index: *index,
                hash: hash.as_byte_array().to_vec(),
                funding_txid: funding_txid.to_byte_array().to_vec(),
                funding_vout: *funding_vout,
                operator_pk: operator_pk.serialize().to_vec(),
                wots_pks: wots_pks.to_flattened_bytes().to_vec(),
            }),
            Self::Musig2NoncesExchange { session_id, nonces } => {
                ProtoGossipsubMsgBody::Nonce(ProtoMusig2NoncesExchange {
                    session_id: session_id.to_vec(),
                    pub_nonces: nonces.iter().map(|n| n.serialize().to_vec()).collect(),
                })
            }
            Self::Musig2SignaturesExchange {
                session_id,
                signatures,
            } => ProtoGossipsubMsgBody::Sigs(ProtoMusig2SignaturesExchange {
                session_id: session_id.to_vec(),
                partial_sigs: signatures.iter().map(|s| s.serialize().to_vec()).collect(),
            }),
        }
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
                let operator_pk = operator_pk.serialize().to_lower_hex_string();
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
                let hash = hash.as_byte_array().to_lower_hex_string();
                let operator_pk = operator_pk.serialize().to_lower_hex_string();
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
                let operator_pk = operator_pk.serialize().to_lower_hex_string();
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
                let hash = hash.as_byte_array().to_lower_hex_string();
                let operator_pk = operator_pk.serialize().to_lower_hex_string();
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
#[derive(Clone)]
pub struct GossipsubMsg {
    /// Operator's signature of the message.
    pub signature: Vec<u8>,

    /// Operator's P2P public key.
    pub key: P2POperatorPubKey,

    /// Unsigned payload.
    pub unsigned: UnsignedGossipsubMsg,
}

impl GossipsubMsg {
    /// Tries to decode a Gossipsub message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let msg = ProtoGossipMsg::decode(bytes)?;
        let Some(body) = msg.body else {
            return Err(DecodeError::new("Message with empty body"));
        };

        let kind = UnsignedGossipsubMsg::from_msg_proto(&body)?;
        let key = msg.key.into();

        Ok(Self {
            signature: msg.signature,
            key,
            unsigned: kind,
        })
    }

    /// Tries to decode a Gossipsub message from a protobuf message.
    pub fn from_proto(msg: ProtoGossipMsg) -> Result<Self, DecodeError> {
        Ok(Self {
            signature: msg.signature,
            key: msg.key.into(),
            unsigned: UnsignedGossipsubMsg::from_msg_proto(&msg.body.unwrap())?,
        })
    }

    /// Converts a Gossipsub message into a protobuf message.
    pub fn into_raw(self) -> ProtoGossipMsg {
        ProtoGossipMsg {
            key: self.key.into(),
            signature: self.signature,
            body: Some(self.unsigned.to_raw()),
        }
    }

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
