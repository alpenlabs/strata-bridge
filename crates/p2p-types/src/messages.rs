//! Message types for P2P communication with compile-time type safety.

use std::fmt;

use bitcoin::hashes::Hash;
use libp2p_identity::ed25519;
use proptest_derive::Arbitrary;
use rkyv::{Archive, Deserialize, Serialize};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx, P2POperatorPubKey};

use crate::{
    unstaking_data::UnstakingInput, GraphData, PartialSignature, PayoutDescriptor, PubNonce,
};

/// Signing context discriminator for cryptographic domain separation.
///
/// Used by both [`MuSig2Nonce`] and [`MuSig2Partial`] to bind signatures
/// to their intended context.
#[repr(u8)]
enum SigningContext {
    /// Deposit transaction signing.
    Deposit = 0x00,
    /// Cooperative payout signing.
    Payout = 0x01,
    /// Transaction graph signing.
    Graph = 0x02,
    /// Unstaking graph signing.
    Unstake = 0x03,
}

/// Gossipsub message kind discriminator for cryptographic domain separation.
///
/// Used by [`UnsignedGossipsubMsg`] to bind signatures to their intended
/// message type.
#[repr(u8)]
enum GossipsubMsgKind {
    /// Payout descriptor exchange.
    PayoutDescriptor = 0x00,
    /// MuSig2 nonces exchange.
    Musig2Nonces = 0x01,
    /// MuSig2 partial signatures exchange.
    Musig2Signatures = 0x02,
    /// Graph data exchange.
    GraphDataExchange = 0x03,
    /// Nag request exchange.
    NagRequest = 0x04,
    /// Unstaking graph data exchange.
    UnstakingDataExchange = 0x05,
}

/// Nag request payload discriminator for cryptographic domain separation.
///
/// Used by [`NagRequestPayload`] to bind signatures to their intended
/// nag request type.
#[repr(u8)]
enum NagPayloadKind {
    /// Request missing deposit nonce.
    DepositNonce = 0x00,
    /// Request missing deposit partial signature.
    DepositPartial = 0x01,
    /// Request missing payout nonce.
    PayoutNonce = 0x02,
    /// Request missing payout partial signature.
    PayoutPartial = 0x03,
    /// Request graph data.
    GraphData = 0x04,
    /// Request missing graph nonces.
    GraphNonces = 0x05,
    /// Request missing graph partial signatures.
    GraphPartials = 0x06,
    /// Request missing unstaking graph data.
    UnstakingData = 0x07,
    /// Request missing unstaking graph nonces.
    UnstakingNonces = 0x08,
    /// Request missing unstaking graph partial signatures.
    UnstakingPartials = 0x09,
}

/// MuSig2 nonce variants for different signing contexts.
#[derive(Clone, Archive, Serialize, Deserialize, Arbitrary)]
pub enum MuSig2Nonce {
    /// Single nonce for deposit transaction signing.
    Deposit {
        /// The deposit index for identifying the deposit transaction.
        deposit_idx: DepositIdx,
        /// The public nonce.
        nonce: PubNonce,
    },
    /// Single nonce for cooperative payout signing.
    Payout {
        /// The deposit index for identifying the cooperative payout transaction.
        deposit_idx: DepositIdx,
        /// The public nonce.
        nonce: PubNonce,
    },
    /// Multiple nonces for graph signing (one per graph transaction input).
    Graph {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,
        /// One nonce per transaction input in the graph.
        nonces: Vec<PubNonce>,
    },
    /// Multiple nonces for unstaking graph signing (one per graph transaction input).
    Unstake {
        /// The index of the staking operator.
        operator_idx: OperatorIdx,
        /// One nonce per transaction input in the unstaking graph.
        nonces: Vec<PubNonce>,
    },
}

impl MuSig2Nonce {
    /// Returns the content bytes for signing.
    ///
    /// Includes a single-byte discriminator to cryptographically bind the signature
    /// to the message type, providing domain separation between variants.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Deposit { deposit_idx, nonce } => {
                buf.push(SigningContext::Deposit as u8);
                buf.extend(deposit_idx.to_le_bytes());
                buf.extend(nonce.to_bytes());
            }
            Self::Payout { deposit_idx, nonce } => {
                buf.push(SigningContext::Payout as u8);
                buf.extend(deposit_idx.to_le_bytes());
                buf.extend(nonce.to_bytes());
            }
            Self::Graph { graph_idx, nonces } => {
                buf.push(SigningContext::Graph as u8);
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(graph_idx.deposit.to_le_bytes());
                for nonce in nonces {
                    buf.extend(nonce.to_bytes());
                }
            }
            Self::Unstake {
                operator_idx,
                nonces,
            } => {
                buf.push(SigningContext::Unstake as u8);
                buf.extend(operator_idx.to_le_bytes());
                for nonce in nonces {
                    buf.extend(nonce.to_bytes());
                }
            }
        }
        buf
    }
}

impl fmt::Debug for MuSig2Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deposit { deposit_idx, .. } => {
                write!(f, "MuSig2Nonce::Deposit(deposit_idx: {deposit_idx})")
            }
            Self::Payout { deposit_idx, .. } => {
                write!(f, "MuSig2Nonce::Payout(deposit_idx: {deposit_idx})")
            }
            Self::Graph { graph_idx, nonces } => {
                write!(
                    f,
                    "MuSig2Nonce::Graph(graph_idx: ({}, {}), nonces: {})",
                    graph_idx.operator,
                    graph_idx.deposit,
                    nonces.len()
                )
            }
            Self::Unstake {
                operator_idx,
                nonces,
            } => {
                write!(
                    f,
                    "MuSig2Nonce::Unstake(operator_idx: {}, nonces: {})",
                    operator_idx,
                    nonces.len()
                )
            }
        }
    }
}

/// MuSig2 partial signature variants for different signing contexts.
#[derive(Clone, Archive, Serialize, Deserialize, Arbitrary)]
pub enum MuSig2Partial {
    /// Single partial for deposit transaction signing.
    Deposit {
        /// The deposit index for identifying the deposit transaction.
        deposit_idx: DepositIdx,
        /// The partial signature.
        partial: PartialSignature,
    },
    /// Single partial for cooperative payout signing.
    Payout {
        /// The deposit index for identifying the cooperative payout transaction.
        deposit_idx: DepositIdx,
        /// The partial signature.
        partial: PartialSignature,
    },
    /// Multiple partials for graph signing (one per graph transaction input).
    Graph {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,
        /// One partial signature per transaction input in the graph.
        partials: Vec<PartialSignature>,
    },
    /// Multiple partials for unstaking graph signing (one per graph transaction input).
    Unstake {
        /// The index of the staking operator.
        operator_idx: OperatorIdx,
        /// One partial signature per transaction input in the unstaking graph.
        partials: Vec<PartialSignature>,
    },
}

impl MuSig2Partial {
    /// Returns the content bytes for signing.
    ///
    /// Includes a single-byte discriminator to cryptographically bind the signature
    /// to the message type, providing domain separation between Deposit/Payout/Graph partials.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Deposit {
                deposit_idx,
                partial,
            } => {
                buf.push(SigningContext::Deposit as u8);
                buf.extend(deposit_idx.to_le_bytes());
                buf.extend(partial.to_bytes());
            }
            Self::Payout {
                deposit_idx,
                partial,
            } => {
                buf.push(SigningContext::Payout as u8);
                buf.extend(deposit_idx.to_le_bytes());
                buf.extend(partial.to_bytes());
            }
            Self::Graph {
                graph_idx,
                partials,
            } => {
                buf.push(SigningContext::Graph as u8);
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(graph_idx.deposit.to_le_bytes());
                for partial in partials {
                    buf.extend(partial.to_bytes());
                }
            }
            Self::Unstake {
                operator_idx,
                partials,
            } => {
                buf.push(SigningContext::Unstake as u8);
                buf.extend(operator_idx.to_le_bytes());
                for partial in partials {
                    buf.extend(partial.to_bytes());
                }
            }
        }
        buf
    }
}

impl fmt::Debug for MuSig2Partial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deposit { deposit_idx, .. } => {
                write!(f, "MuSig2Partial::Deposit(deposit_idx: {deposit_idx})")
            }
            Self::Payout { deposit_idx, .. } => {
                write!(f, "MuSig2Partial::Payout(deposit_idx: {deposit_idx})")
            }
            Self::Graph {
                graph_idx,
                partials,
            } => {
                write!(
                    f,
                    "MuSig2Partial::Graph(graph_idx: ({}, {}), partials: {})",
                    graph_idx.operator,
                    graph_idx.deposit,
                    partials.len()
                )
            }
            Self::Unstake {
                operator_idx,
                partials,
            } => {
                write!(
                    f,
                    "MuSig2Partial::Unstake(operator_idx: {}, partials: {})",
                    operator_idx,
                    partials.len()
                )
            }
        }
    }
}

/// Nag request payload for describing type of data requested.
#[derive(Clone, PartialEq, Eq, Archive, Serialize, Deserialize, Arbitrary)]
pub enum NagRequestPayload {
    /// Request missing deposit nonce.
    DepositNonce {
        /// The deposit index for identifying the deposit.
        deposit_idx: DepositIdx,
    },
    /// Request missing deposit partial signature.
    DepositPartial {
        /// The deposit index for identifying the deposit.
        deposit_idx: DepositIdx,
    },
    /// Request missing payout nonce.
    PayoutNonce {
        /// The deposit index for identifying the payout.
        deposit_idx: DepositIdx,
    },
    /// Request missing payout partial signature.
    PayoutPartial {
        /// The deposit index for identifying the payout.
        deposit_idx: DepositIdx,
    },
    /// Request graph data generation.
    GraphData {
        /// The graph index for identifying the graph instance.
        graph_idx: GraphIdx,
    },
    /// Request missing graph nonces.
    GraphNonces {
        /// The graph index for identifying the graph instance.
        graph_idx: GraphIdx,
    },
    /// Request missing graph partial signatures.
    GraphPartials {
        /// The graph index for identifying the graph instance.
        graph_idx: GraphIdx,
    },
    /// Request missing unstaking graph data.
    UnstakingData {
        /// The index of the staking operator whose unstaking graph data is missing.
        operator_idx: OperatorIdx,
    },
    /// Request missing unstaking graph nonces.
    UnstakingNonces {
        /// The index of the staking operator whose unstaking graph nonces are missing.
        operator_idx: OperatorIdx,
    },
    /// Request missing unstaking graph partial signatures.
    UnstakingPartials {
        /// The index of the staking operator whose unstaking graph partial signatures are missing.
        operator_idx: OperatorIdx,
    },
}

impl NagRequestPayload {
    /// Returns the content bytes for signing.
    ///
    /// Includes a single-byte discriminator to cryptographically bind the signature
    /// to the nag request type, providing domain separation between variants.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::DepositNonce { deposit_idx } => {
                buf.push(NagPayloadKind::DepositNonce as u8);
                buf.extend(deposit_idx.to_le_bytes());
            }
            Self::DepositPartial { deposit_idx } => {
                buf.push(NagPayloadKind::DepositPartial as u8);
                buf.extend(deposit_idx.to_le_bytes());
            }
            Self::PayoutNonce { deposit_idx } => {
                buf.push(NagPayloadKind::PayoutNonce as u8);
                buf.extend(deposit_idx.to_le_bytes());
            }
            Self::PayoutPartial { deposit_idx } => {
                buf.push(NagPayloadKind::PayoutPartial as u8);
                buf.extend(deposit_idx.to_le_bytes());
            }
            Self::GraphData { graph_idx } => {
                buf.push(NagPayloadKind::GraphData as u8);
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(graph_idx.deposit.to_le_bytes());
            }
            Self::GraphNonces { graph_idx } => {
                buf.push(NagPayloadKind::GraphNonces as u8);
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(graph_idx.deposit.to_le_bytes());
            }
            Self::GraphPartials { graph_idx } => {
                buf.push(NagPayloadKind::GraphPartials as u8);
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(graph_idx.deposit.to_le_bytes());
            }
            Self::UnstakingData { operator_idx } => {
                buf.push(NagPayloadKind::UnstakingData as u8);
                buf.extend(operator_idx.to_le_bytes());
            }
            Self::UnstakingNonces { operator_idx } => {
                buf.push(NagPayloadKind::UnstakingNonces as u8);
                buf.extend(operator_idx.to_le_bytes());
            }
            Self::UnstakingPartials { operator_idx } => {
                buf.push(NagPayloadKind::UnstakingPartials as u8);
                buf.extend(operator_idx.to_le_bytes());
            }
        }
        buf
    }
}

impl fmt::Debug for NagRequestPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DepositNonce { deposit_idx } => {
                write!(
                    f,
                    "NagRequestPayload::DepositNonce(deposit_idx: {deposit_idx})"
                )
            }
            Self::DepositPartial { deposit_idx } => {
                write!(
                    f,
                    "NagRequestPayload::DepositPartial(deposit_idx: {deposit_idx})"
                )
            }
            Self::PayoutNonce { deposit_idx } => {
                write!(
                    f,
                    "NagRequestPayload::PayoutNonce(deposit_idx: {deposit_idx})"
                )
            }
            Self::PayoutPartial { deposit_idx } => {
                write!(
                    f,
                    "NagRequestPayload::PayoutPartial(deposit_idx: {deposit_idx})"
                )
            }
            Self::GraphData { graph_idx } => {
                write!(
                    f,
                    "NagRequestPayload::GraphData(graph_idx: ({}, {}))",
                    graph_idx.operator, graph_idx.deposit
                )
            }
            Self::GraphNonces { graph_idx } => {
                write!(
                    f,
                    "NagRequestPayload::GraphNonces(graph_idx: ({}, {}))",
                    graph_idx.operator, graph_idx.deposit
                )
            }
            Self::GraphPartials { graph_idx } => {
                write!(
                    f,
                    "NagRequestPayload::GraphPartials(graph_idx: ({}, {}))",
                    graph_idx.operator, graph_idx.deposit
                )
            }
            Self::UnstakingData { operator_idx } => {
                write!(
                    f,
                    "NagRequestPayload::UnstakingData(operator_idx: {})",
                    operator_idx
                )
            }
            Self::UnstakingNonces { operator_idx } => {
                write!(
                    f,
                    "NagRequestPayload::UnstakingNonces(operator_idx: {})",
                    operator_idx
                )
            }
            Self::UnstakingPartials { operator_idx } => {
                write!(
                    f,
                    "NagRequestPayload::UnstakingPartials(operator_idx: {})",
                    operator_idx
                )
            }
        }
    }
}

/// Nag request message for requesting missing data from peers.
#[derive(Clone, PartialEq, Eq, Archive, Serialize, Deserialize, Arbitrary)]
pub struct NagRequest {
    /// The intended recipient of this nag request.
    pub recipient: P2POperatorPubKey,
    /// The payload describing what data is being requested.
    pub payload: NagRequestPayload,
}

impl NagRequest {
    /// Returns the content bytes for signing.
    ///
    /// Includes the recipient public key followed by the payload content bytes.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.recipient.as_ref());
        buf.extend(self.payload.content_bytes());
        buf
    }
}

impl fmt::Debug for NagRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NagRequest(recipient: {}, payload: {:?})",
            self.recipient, self.payload
        )
    }
}

/// Unsigned gossipsub messages.
#[derive(Clone, Archive, Serialize, Deserialize, Arbitrary)]
#[rkyv(attr(expect(clippy::enum_variant_names)))]
pub enum UnsignedGossipsubMsg {
    /// Payout descriptor exchange.
    PayoutDescriptorExchange {
        /// The deposit index for identifying the payout context.
        deposit_idx: DepositIdx,
        /// The operator index.
        operator_idx: OperatorIdx,
        /// The operator's payout descriptor.
        operator_desc: PayoutDescriptor,
    },

    /// Data required to construct the transaction graph.
    GraphDataExchange {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,

        /// The deposit-time data required to construct the graph.
        graph_data: GraphData,
    },

    /// Data required to construct the Unstaking Graph.
    UnstakingDataExchange {
        /// The index of the staking operator.
        operator_idx: OperatorIdx,
        /// The input that funds the stake transaction.
        unstaking_input: UnstakingInput,
    },

    /// MuSig2 nonces exchange.
    Musig2NoncesExchange(MuSig2Nonce),

    /// MuSig2 partial signatures exchange.
    Musig2SignaturesExchange(MuSig2Partial),

    /// Nag request exchange.
    NagRequestExchange(NagRequest),
}

impl UnsignedGossipsubMsg {
    /// Returns the canonical byte representation for signing.
    ///
    /// Includes a single-byte discriminator to cryptographically bind the signature
    /// to the message type, providing domain separation between message variants.
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::PayoutDescriptorExchange {
                deposit_idx,
                operator_idx,
                operator_desc,
            } => {
                buf.push(GossipsubMsgKind::PayoutDescriptor as u8);
                buf.extend(deposit_idx.to_le_bytes());
                buf.extend(operator_idx.to_le_bytes());
                buf.extend(operator_desc.content_bytes());
            }
            Self::GraphDataExchange {
                graph_idx,
                graph_data,
            } => {
                let GraphData {
                    funding_outpoint,
                    adaptor_pubkeys,
                    fault_pubkeys,
                } = graph_data;
                buf.push(GossipsubMsgKind::GraphDataExchange as u8);
                buf.extend(graph_idx.deposit.to_le_bytes());
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(funding_outpoint.txid.to_raw_hash().to_byte_array()); // txid
                buf.extend(funding_outpoint.vout.to_le_bytes()); // vout
                buf.extend((adaptor_pubkeys.len() as u32).to_le_bytes());
                for adaptor_pubkey in adaptor_pubkeys {
                    buf.extend(adaptor_pubkey.to_bytes());
                }
                buf.extend((fault_pubkeys.len() as u32).to_le_bytes());
                for fault_pubkey in fault_pubkeys {
                    buf.extend(fault_pubkey.to_bytes());
                }
            }
            Self::UnstakingDataExchange {
                operator_idx,
                unstaking_input,
            } => {
                buf.push(GossipsubMsgKind::UnstakingDataExchange as u8);
                buf.extend(operator_idx.to_le_bytes());
                let UnstakingInput {
                    stake_funds,
                    unstaking_image,
                    unstaking_operator_desc,
                } = unstaking_input;
                buf.extend(stake_funds.txid.to_raw_hash().to_byte_array());
                buf.extend(stake_funds.vout.to_le_bytes());
                buf.extend(unstaking_image.to_byte_array());
                buf.extend(unstaking_operator_desc.content_bytes());
            }
            Self::Musig2NoncesExchange(nonce) => {
                buf.push(GossipsubMsgKind::Musig2Nonces as u8);
                buf.extend(nonce.content_bytes());
            }
            Self::Musig2SignaturesExchange(partial) => {
                buf.push(GossipsubMsgKind::Musig2Signatures as u8);
                buf.extend(partial.content_bytes());
            }
            Self::NagRequestExchange(nag) => {
                buf.push(GossipsubMsgKind::NagRequest as u8);
                buf.extend(nag.content_bytes());
            }
        }
        buf
    }

    /// Signs the message with an ed25519 keypair.
    pub fn sign_ed25519(&self, keypair: &ed25519::Keypair) -> GossipsubMsg {
        let content = self.content_bytes();
        let signature = keypair.sign(&content);

        GossipsubMsg {
            key: keypair.public().clone().into(),
            signature,
            unsigned: self.clone(),
        }
    }
}

impl fmt::Debug for UnsignedGossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayoutDescriptorExchange {
                deposit_idx,
                operator_idx,
                operator_desc,
            } => {
                write!(
                    f,
                    "PayoutDescriptorExchange(deposit_idx: {deposit_idx}, operator: {operator_idx}, desc: {operator_desc})"
                )
            }
            Self::GraphDataExchange {
                graph_idx,
                graph_data,
            } => {
                write!(
                    f,
                    "GraphDataExchange(graph_idx: {:?}, graph_data: {:?})",
                    graph_idx, graph_data
                )
            }
            Self::UnstakingDataExchange {
                operator_idx,
                unstaking_input,
            } => {
                write!(
                    f,
                    "UnstakingDataExchange(operator_idx: {}, unstaking_input: {:?})",
                    operator_idx, unstaking_input
                )
            }
            Self::Musig2NoncesExchange(nonce) => {
                write!(f, "Musig2NoncesExchange({nonce:?})")
            }
            Self::Musig2SignaturesExchange(partial) => {
                write!(f, "Musig2SignaturesExchange({partial:?})")
            }
            Self::NagRequestExchange(nag) => {
                write!(f, "NagRequestExchange({nag:?})")
            }
        }
    }
}

impl fmt::Display for UnsignedGossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Signed gossipsub message wrapper.
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct GossipsubMsg {
    /// ED25519 signature over the message content (64 bytes).
    pub signature: Vec<u8>,

    /// Sender's P2P public key (32 bytes).
    pub key: P2POperatorPubKey,

    /// The unsigned message payload.
    pub unsigned: UnsignedGossipsubMsg,
}

impl GossipsubMsg {
    /// Returns the content bytes for signature verification.
    pub fn content_bytes(&self) -> Vec<u8> {
        self.unsigned.content_bytes()
    }

    /// Verifies the signature using the embedded public key.
    pub fn verify(&self) -> bool {
        self.key.verify(&self.content_bytes(), &self.signature)
    }
}

impl fmt::Debug for GossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GossipsubMsg(key: {}, unsigned: {:?})",
            self.key, self.unsigned
        )
    }
}

impl fmt::Display for GossipsubMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::sha256, OutPoint, Txid};
    use libp2p_identity::ed25519::Keypair;
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_test_utils::{
        bitcoin::generate_xonly_pubkey,
        musig2::{generate_partial_signature, generate_pubnonce},
    };

    use super::*;
    use crate::{GraphData, PartialSignature, PayoutDescriptor, PubNonce, XOnlyPubKey};

    // Helper to create a test GraphData with a random funding outpoint and random keys.
    fn test_graph_data(txid_bytes: [u8; 32], vout: u32, n_watchtowers: usize) -> GraphData {
        use bitcoin::hashes::Hash as _;

        let adaptor_pubkeys = (0..n_watchtowers)
            .map(|_| XOnlyPubKey::from(generate_xonly_pubkey()))
            .collect();
        let fault_pubkeys = (0..n_watchtowers)
            .map(|_| XOnlyPubKey::from(generate_xonly_pubkey()))
            .collect();
        GraphData::new(
            OutPoint {
                txid: Txid::from_byte_array(txid_bytes),
                vout,
            },
            adaptor_pubkeys,
            fault_pubkeys,
        )
    }

    // Helper to generate random ed25519 keypair for message signing tests.
    fn test_keypair() -> Keypair {
        let mut secret_bytes: [u8; 32] = OsRng.gen();
        let secret =
            libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes).unwrap();
        Keypair::from(secret)
    }

    // Helper to create a test PubNonce using test-utils.
    fn test_pubnonce() -> PubNonce {
        generate_pubnonce().into()
    }

    // Helper to create a test PartialSignature using test-utils.
    fn test_partial_signature() -> PartialSignature {
        generate_partial_signature().into()
    }

    // Helper to create a test PayoutDescriptor.
    fn test_payout_descriptor() -> PayoutDescriptor {
        PayoutDescriptor::new(vec![1, 2, 3, 4, 5])
    }

    // ==================== Discriminator Coverage Tests ====================

    // Verifies every MuSig2Nonce variant uses the correct signing context discriminator.
    #[test]
    fn musig2_nonce_variant_discriminators_are_stable() {
        let cases = vec![
            (
                "Deposit",
                MuSig2Nonce::Deposit {
                    deposit_idx: 42,
                    nonce: test_pubnonce(),
                },
                SigningContext::Deposit as u8,
            ),
            (
                "Payout",
                MuSig2Nonce::Payout {
                    deposit_idx: 43,
                    nonce: test_pubnonce(),
                },
                SigningContext::Payout as u8,
            ),
            (
                "Graph",
                MuSig2Nonce::Graph {
                    graph_idx: GraphIdx {
                        operator: 7,
                        deposit: 11,
                    },
                    nonces: vec![test_pubnonce()],
                },
                SigningContext::Graph as u8,
            ),
            (
                "Unstake",
                MuSig2Nonce::Unstake {
                    operator_idx: 13,
                    nonces: vec![test_pubnonce()],
                },
                SigningContext::Unstake as u8,
            ),
        ];

        for (name, nonce, expected_prefix) in cases {
            let content = nonce.content_bytes();
            assert_eq!(
                content[0], expected_prefix,
                "{} discriminator should be {:#04x}",
                name, expected_prefix
            );
        }
    }

    // Verifies every MuSig2Partial variant uses the correct signing context discriminator.
    #[test]
    fn musig2_partial_variant_discriminators_are_stable() {
        let cases = vec![
            (
                "Deposit",
                MuSig2Partial::Deposit {
                    deposit_idx: 42,
                    partial: test_partial_signature(),
                },
                SigningContext::Deposit as u8,
            ),
            (
                "Payout",
                MuSig2Partial::Payout {
                    deposit_idx: 43,
                    partial: test_partial_signature(),
                },
                SigningContext::Payout as u8,
            ),
            (
                "Graph",
                MuSig2Partial::Graph {
                    graph_idx: GraphIdx {
                        operator: 7,
                        deposit: 11,
                    },
                    partials: vec![test_partial_signature()],
                },
                SigningContext::Graph as u8,
            ),
            (
                "Unstake",
                MuSig2Partial::Unstake {
                    operator_idx: 13,
                    partials: vec![test_partial_signature()],
                },
                SigningContext::Unstake as u8,
            ),
        ];

        for (name, partial, expected_prefix) in cases {
            let content = partial.content_bytes();
            assert_eq!(
                content[0], expected_prefix,
                "{} discriminator should be {:#04x}",
                name, expected_prefix
            );
        }
    }

    // Verifies every unsigned gossipsub message variant uses the correct message kind byte.
    #[test]
    fn unsigned_gossipsub_msg_variant_discriminators_are_stable() {
        use bitcoin::hashes::Hash as _;

        let cases = vec![
            (
                "PayoutDescriptorExchange",
                UnsignedGossipsubMsg::PayoutDescriptorExchange {
                    deposit_idx: 1,
                    operator_idx: 2,
                    operator_desc: test_payout_descriptor(),
                },
                GossipsubMsgKind::PayoutDescriptor as u8,
            ),
            (
                "GraphDataExchange",
                UnsignedGossipsubMsg::GraphDataExchange {
                    graph_idx: GraphIdx {
                        operator: 3,
                        deposit: 4,
                    },
                    graph_data: test_graph_data([0xAB; 32], 5, 2),
                },
                GossipsubMsgKind::GraphDataExchange as u8,
            ),
            (
                "UnstakingDataExchange",
                UnsignedGossipsubMsg::UnstakingDataExchange {
                    operator_idx: 6,
                    unstaking_input: UnstakingInput {
                        stake_funds: OutPoint {
                            txid: Txid::from_byte_array([0xCD; 32]),
                            vout: 7,
                        },
                        unstaking_image: sha256::Hash::from_byte_array([0xEF; 32]),
                        unstaking_operator_desc: test_payout_descriptor(),
                    },
                },
                GossipsubMsgKind::UnstakingDataExchange as u8,
            ),
            (
                "Musig2NoncesExchange",
                UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Deposit {
                    deposit_idx: 8,
                    nonce: test_pubnonce(),
                }),
                GossipsubMsgKind::Musig2Nonces as u8,
            ),
            (
                "Musig2SignaturesExchange",
                UnsignedGossipsubMsg::Musig2SignaturesExchange(MuSig2Partial::Deposit {
                    deposit_idx: 9,
                    partial: test_partial_signature(),
                }),
                GossipsubMsgKind::Musig2Signatures as u8,
            ),
            (
                "NagRequestExchange",
                UnsignedGossipsubMsg::NagRequestExchange(NagRequest {
                    recipient: P2POperatorPubKey::from(vec![0x11; 32]),
                    payload: NagRequestPayload::DepositNonce { deposit_idx: 10 },
                }),
                GossipsubMsgKind::NagRequest as u8,
            ),
        ];

        for (name, msg, expected_prefix) in cases {
            let content = msg.content_bytes();
            assert_eq!(
                content[0], expected_prefix,
                "{} discriminator should be {:#04x}",
                name, expected_prefix
            );
        }
    }

    // Verifies every nag payload variant uses the correct payload discriminator.
    #[test]
    fn nag_request_payload_variant_discriminators_are_stable() {
        let cases = vec![
            (
                "DepositNonce",
                NagRequestPayload::DepositNonce { deposit_idx: 1 },
                NagPayloadKind::DepositNonce as u8,
            ),
            (
                "DepositPartial",
                NagRequestPayload::DepositPartial { deposit_idx: 2 },
                NagPayloadKind::DepositPartial as u8,
            ),
            (
                "PayoutNonce",
                NagRequestPayload::PayoutNonce { deposit_idx: 3 },
                NagPayloadKind::PayoutNonce as u8,
            ),
            (
                "PayoutPartial",
                NagRequestPayload::PayoutPartial { deposit_idx: 4 },
                NagPayloadKind::PayoutPartial as u8,
            ),
            (
                "GraphData",
                NagRequestPayload::GraphData {
                    graph_idx: GraphIdx {
                        operator: 5,
                        deposit: 6,
                    },
                },
                NagPayloadKind::GraphData as u8,
            ),
            (
                "GraphNonces",
                NagRequestPayload::GraphNonces {
                    graph_idx: GraphIdx {
                        operator: 7,
                        deposit: 8,
                    },
                },
                NagPayloadKind::GraphNonces as u8,
            ),
            (
                "GraphPartials",
                NagRequestPayload::GraphPartials {
                    graph_idx: GraphIdx {
                        operator: 9,
                        deposit: 10,
                    },
                },
                NagPayloadKind::GraphPartials as u8,
            ),
            (
                "UnstakingData",
                NagRequestPayload::UnstakingData { operator_idx: 11 },
                NagPayloadKind::UnstakingData as u8,
            ),
            (
                "UnstakingNonces",
                NagRequestPayload::UnstakingNonces { operator_idx: 12 },
                NagPayloadKind::UnstakingNonces as u8,
            ),
            (
                "UnstakingPartials",
                NagRequestPayload::UnstakingPartials { operator_idx: 13 },
                NagPayloadKind::UnstakingPartials as u8,
            ),
        ];

        for (name, payload, expected_prefix) in cases {
            let content = payload.content_bytes();
            assert_eq!(
                content[0], expected_prefix,
                "{} discriminator should be {:#04x}",
                name, expected_prefix
            );
        }
    }

    // ==================== Content Serialization Tests ====================

    // Verifies PayoutDescriptorExchange serializes all fields in canonical order.
    #[test]
    fn unsigned_msg_payout_descriptor_serializes_all_fields() {
        let desc = test_payout_descriptor();
        let desc_bytes = desc.content_bytes().to_vec();
        let deposit_idx: DepositIdx = 7;
        let operator_idx: OperatorIdx = 3;

        let msg = UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx,
            operator_idx,
            operator_desc: desc,
        };
        let content = msg.content_bytes();

        let expected_len = 1 + 4 + 4 + desc_bytes.len();
        assert_eq!(
            content.len(),
            expected_len,
            "PayoutDescriptorExchange should be {} bytes",
            expected_len
        );
        assert_eq!(
            content[0],
            GossipsubMsgKind::PayoutDescriptor as u8,
            "PayoutDescriptorExchange discriminator should be 0x00"
        );
        assert_eq!(
            &content[1..5],
            &deposit_idx.to_le_bytes(),
            "deposit_idx should be serialized as little-endian u32"
        );
        assert_eq!(
            &content[5..9],
            &operator_idx.to_le_bytes(),
            "operator_idx should be serialized as little-endian u32"
        );
        assert_eq!(
            &content[9..],
            &desc_bytes,
            "operator_desc bytes should follow the fixed-width header"
        );
    }

    // Verifies GraphDataExchange serializes as
    // [kind][deposit][operator][txid][vout][adaptor_pubkey][n_faults][fault_pubkey...].
    #[test]
    fn unsigned_msg_graph_data_serializes_all_fields() {
        let txid_bytes = [0xAC; 32];
        let vout = 9u32;
        let n_watchtowers = 3;
        let graph_idx = GraphIdx {
            operator: 3,
            deposit: 7,
        };
        let graph_data = test_graph_data(txid_bytes, vout, n_watchtowers);
        let adaptor_bytes: Vec<[u8; 32]> = graph_data
            .adaptor_pubkeys
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        let fault_bytes: Vec<[u8; 32]> = graph_data
            .fault_pubkeys
            .iter()
            .map(|k| k.to_bytes())
            .collect();

        let msg = UnsignedGossipsubMsg::GraphDataExchange {
            graph_idx,
            graph_data,
        };
        let content = msg.content_bytes();

        let expected_len = 1 + 4 + 4 + 32 + 4 + 4 + (n_watchtowers * 32) + 4 + (n_watchtowers * 32);
        assert_eq!(
            content.len(),
            expected_len,
            "GraphDataExchange should be {} bytes",
            expected_len
        );

        let mut offset = 0;
        assert_eq!(
            content[offset],
            GossipsubMsgKind::GraphDataExchange as u8,
            "GraphDataExchange discriminator should be 0x03"
        );
        offset += 1;
        assert_eq!(
            &content[offset..offset + 4],
            &graph_idx.deposit.to_le_bytes(),
            "deposit_idx should be serialized before operator_idx"
        );
        offset += 4;
        assert_eq!(
            &content[offset..offset + 4],
            &graph_idx.operator.to_le_bytes(),
            "operator_idx should follow deposit_idx"
        );
        offset += 4;
        assert_eq!(
            &content[offset..offset + 32],
            &txid_bytes,
            "funding_outpoint txid should match"
        );
        offset += 32;
        assert_eq!(
            &content[offset..offset + 4],
            &vout.to_le_bytes(),
            "funding_outpoint vout should be serialized as little-endian u32"
        );
        offset += 4;
        assert_eq!(
            &content[offset..offset + 4],
            &(n_watchtowers as u32).to_le_bytes(),
            "adaptor_pubkeys length prefix should be little-endian u32"
        );
        offset += 4;
        for (i, adaptor) in adaptor_bytes.iter().enumerate() {
            assert_eq!(
                &content[offset..offset + 32],
                adaptor,
                "adaptor_pubkey[{i}] should match"
            );
            offset += 32;
        }
        assert_eq!(
            &content[offset..offset + 4],
            &(n_watchtowers as u32).to_le_bytes(),
            "fault_pubkeys length prefix should be little-endian u32"
        );
        offset += 4;
        for (i, fault) in fault_bytes.iter().enumerate() {
            assert_eq!(
                &content[offset..offset + 32],
                fault,
                "fault_pubkey[{i}] should match"
            );
            offset += 32;
        }
    }

    // Verifies UnstakingDataExchange serializes all fields of UnstakingInput.
    #[test]
    fn unsigned_msg_unstaking_data_serializes_all_fields() {
        use bitcoin::hashes::Hash as _;

        let desc = test_payout_descriptor();
        let desc_bytes = desc.content_bytes().to_vec();

        let image = [0xAB; 32];
        let stake_funds_txid = [0xCD; 32];
        let stake_funds_vout = 1;
        let stake_funds = OutPoint {
            txid: Txid::from_byte_array(stake_funds_txid),
            vout: stake_funds_vout,
        };
        let unstaking_input = UnstakingInput {
            stake_funds,
            unstaking_image: sha256::Hash::from_byte_array(image),
            unstaking_operator_desc: desc,
        };

        let operator_idx: OperatorIdx = 3;
        let msg = UnsignedGossipsubMsg::UnstakingDataExchange {
            operator_idx,
            unstaking_input,
        };
        let content = msg.content_bytes();

        // Structure: discriminator (1) + operator_idx (4) + txid (32) + vout (4) + image (32) +
        // desc
        let expected_len = 1 + 4 + 32 + 4 + 32 + desc_bytes.len();
        assert_eq!(
            content.len(),
            expected_len,
            "UnstakingDataExchange should be {} bytes",
            expected_len
        );

        let mut offset = 0;
        assert_eq!(
            content[offset], 0x05,
            "UnstakingDataExchange discriminator should be 0x05"
        );
        offset += 1;
        assert_eq!(
            &content[offset..offset + 4],
            &operator_idx.to_le_bytes(),
            "operator_idx should be serialized as little-endian u32"
        );
        offset += 4;
        assert_eq!(
            &content[offset..offset + 32],
            &stake_funds_txid,
            "stake_funds txid should match"
        );
        offset += 32;
        assert_eq!(
            &content[offset..offset + 4],
            &stake_funds_vout.to_le_bytes(),
            "stake_funds vout should be serialized as little-endian u32"
        );
        offset += 4;
        assert_eq!(
            &content[offset..offset + 32],
            &image,
            "unstaking_image should match"
        );
        offset += 32;
        assert_eq!(
            &content[offset..],
            &desc_bytes,
            "unstaking_operator_desc bytes should match"
        );
    }

    // Verifies MuSig2Nonce::Deposit serializes with correct byte layout.
    #[test]
    fn musig2_nonce_deposit_serializes_correctly() {
        let nonce = MuSig2Nonce::Deposit {
            deposit_idx: 42,
            nonce: test_pubnonce(),
        };
        let content = nonce.content_bytes();

        assert_eq!(
            content.len(),
            1 + 4 + 66,
            "Deposit content should be 71 bytes: discriminator (1) + deposit_idx (4) + nonce (66)"
        );
        assert_eq!(content[0], 0x00, "Deposit discriminator should be 0x00");
        assert_eq!(
            &content[1..5],
            &42u32.to_le_bytes(),
            "deposit_idx should be serialized as little-endian u32"
        );
    }

    // Verifies MuSig2Nonce::Graph serializes all nonces into content bytes.
    #[test]
    fn musig2_nonce_graph_serializes_multiple_nonces() {
        let nonces = vec![test_pubnonce(), test_pubnonce(), test_pubnonce()];
        let nonce = MuSig2Nonce::Graph {
            graph_idx: GraphIdx {
                operator: 10,
                deposit: 20,
            },
            nonces: nonces.clone(),
        };
        let content = nonce.content_bytes();

        // Check structure: discriminator (1) + operator_idx (4) + deposit_idx (4) + nonces (3 * 66)
        assert_eq!(
            content.len(),
            1 + 4 + 4 + 3 * 66,
            "Graph content should be 207 bytes: discriminator (1) + operator_idx (4) + deposit_idx (4) + 3 nonces (198)"
        );
        assert_eq!(content[0], 0x02, "Graph discriminator should be 0x02");
        assert_eq!(
            &content[1..5],
            &10u32.to_le_bytes(),
            "operator_idx should be serialized as little-endian u32"
        );
        assert_eq!(
            &content[5..9],
            &20u32.to_le_bytes(),
            "deposit_idx should be serialized as little-endian u32"
        );
    }

    // Verifies MuSig2Partial::Graph serializes all partials into content bytes.
    #[test]
    fn musig2_partial_graph_serializes_multiple_partials() {
        let partials = vec![test_partial_signature(), test_partial_signature()];
        let partial = MuSig2Partial::Graph {
            graph_idx: GraphIdx {
                operator: 5,
                deposit: 10,
            },
            partials: partials.clone(),
        };
        let content = partial.content_bytes();

        // Check structure: discriminator (1) + operator_idx (4) + deposit_idx (4) + partials (2 *
        // 32)
        assert_eq!(
            content.len(),
            1 + 4 + 4 + 2 * 32,
            "Graph partial content should be 73 bytes: discriminator (1) + operator_idx (4) + deposit_idx (4) + 2 partials (64)"
        );
        assert_eq!(content[0], 0x02, "Graph discriminator should be 0x02");
    }

    // Verifies MuSig2Nonce::Unstake serializes all nonces into content bytes.
    #[test]
    fn musig2_nonce_unstake_serializes_multiple_nonces() {
        let nonces = vec![test_pubnonce(), test_pubnonce(), test_pubnonce()];
        let nonce = MuSig2Nonce::Unstake {
            operator_idx: 10,
            nonces: nonces.clone(),
        };
        let content = nonce.content_bytes();

        // Check structure: discriminator (1) + operator_idx (4) + nonces (3 * 66)
        assert_eq!(
            content.len(),
            1 + 4 + 3 * 66,
            "Unstake nonce content should be 203 bytes: discriminator (1) + operator_idx (4) + 3 nonces (198)"
        );
        assert_eq!(content[0], 0x03, "Unstake discriminator should be 0x03");
        assert_eq!(
            &content[1..5],
            &10u32.to_le_bytes(),
            "operator_idx should be serialized as little-endian u32"
        );
    }

    // Verifies MuSig2Partial::Unstake serializes all partials into content bytes.
    #[test]
    fn musig2_partial_unstake_serializes_multiple_partials() {
        let partials = vec![test_partial_signature(), test_partial_signature()];
        let partial = MuSig2Partial::Unstake {
            operator_idx: 5,
            partials: partials.clone(),
        };
        let content = partial.content_bytes();

        // Check structure: discriminator (1) + operator_idx (4) + partials (2 * 32)
        assert_eq!(
            content.len(),
            1 + 4 + 2 * 32,
            "Unstake partial content should be 69 bytes: discriminator (1) + operator_idx (4) + 2 partials (64)"
        );
        assert_eq!(content[0], 0x03, "Unstake discriminator should be 0x03");
        assert_eq!(
            &content[1..5],
            &5u32.to_le_bytes(),
            "operator_idx should be serialized as little-endian u32"
        );
    }

    // Verifies MuSig2Nonce::Unstake handles empty nonces vector correctly.
    #[test]
    fn empty_nonces_unstake() {
        let nonce = MuSig2Nonce::Unstake {
            operator_idx: 1,
            nonces: vec![],
        };
        let content = nonce.content_bytes();

        // Should just have discriminator + operator_idx
        assert_eq!(
            content.len(),
            1 + 4,
            "Empty unstake nonces should be 5 bytes: discriminator (1) + operator_idx (4)"
        );
    }

    // Verifies MuSig2Partial::Unstake handles empty partials vector correctly.
    #[test]
    fn empty_partials_unstake() {
        let partial = MuSig2Partial::Unstake {
            operator_idx: 1,
            partials: vec![],
        };
        let content = partial.content_bytes();

        // Should just have discriminator + operator_idx
        assert_eq!(
            content.len(),
            1 + 4,
            "Empty unstake partials should be 5 bytes: discriminator (1) + operator_idx (4)"
        );
    }

    // Verifies MuSig2Nonce::Graph handles empty nonces vector correctly.
    #[test]
    fn empty_nonces_graph() {
        let nonce = MuSig2Nonce::Graph {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 1,
            },
            nonces: vec![],
        };
        let content = nonce.content_bytes();

        // Should just have discriminator + graph_idx
        assert_eq!(
            content.len(),
            1 + 4 + 4,
            "Empty graph nonces should be 9 bytes: discriminator (1) + operator_idx (4) + deposit_idx (4)"
        );
    }

    // Verifies MuSig2Partial::Graph handles empty partials vector correctly.
    #[test]
    fn empty_partials_graph() {
        let partial = MuSig2Partial::Graph {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 1,
            },
            partials: vec![],
        };
        let content = partial.content_bytes();

        // Should just have discriminator + graph_idx
        assert_eq!(
            content.len(),
            1 + 4 + 4,
            "Empty graph partials should be 9 bytes: discriminator (1) + operator_idx (4) + deposit_idx (4)"
        );
    }

    // Verifies Musig2NoncesExchange prepends the outer message kind to nonce bytes.
    #[test]
    fn unsigned_msg_musig2_nonces_exchange_wraps_nested_content() {
        let nonce = MuSig2Nonce::Payout {
            deposit_idx: 42,
            nonce: test_pubnonce(),
        };
        let nonce_content = nonce.content_bytes();
        let msg = UnsignedGossipsubMsg::Musig2NoncesExchange(nonce);
        let content = msg.content_bytes();

        assert_eq!(
            content.len(),
            1 + nonce_content.len(),
            "Musig2NoncesExchange should be 1 byte longer than the nested nonce content"
        );
        assert_eq!(
            content[0],
            GossipsubMsgKind::Musig2Nonces as u8,
            "Musig2NoncesExchange discriminator should be 0x01"
        );
        assert_eq!(
            &content[1..],
            &nonce_content,
            "Musig2NoncesExchange should append the nested nonce bytes unchanged"
        );
    }

    // Verifies Musig2SignaturesExchange prepends the outer message kind to partial bytes.
    #[test]
    fn unsigned_msg_musig2_signatures_exchange_wraps_nested_content() {
        let partial = MuSig2Partial::Payout {
            deposit_idx: 42,
            partial: test_partial_signature(),
        };
        let partial_content = partial.content_bytes();
        let msg = UnsignedGossipsubMsg::Musig2SignaturesExchange(partial);
        let content = msg.content_bytes();

        assert_eq!(
            content.len(),
            1 + partial_content.len(),
            "Musig2SignaturesExchange should be 1 byte longer than the nested partial content"
        );
        assert_eq!(
            content[0],
            GossipsubMsgKind::Musig2Signatures as u8,
            "Musig2SignaturesExchange discriminator should be 0x02"
        );
        assert_eq!(
            &content[1..],
            &partial_content,
            "Musig2SignaturesExchange should append the nested partial bytes unchanged"
        );
    }

    // Verifies NagRequestExchange prepends the outer message kind to nag request bytes.
    #[test]
    fn unsigned_msg_nag_request_exchange_wraps_nested_content() {
        let nag = NagRequest {
            recipient: P2POperatorPubKey::from(vec![0xAB; 32]),
            payload: NagRequestPayload::DepositPartial { deposit_idx: 42 },
        };
        let nag_content = nag.content_bytes();
        let msg = UnsignedGossipsubMsg::NagRequestExchange(nag);
        let content = msg.content_bytes();

        assert_eq!(
            content.len(),
            1 + nag_content.len(),
            "NagRequestExchange should be 1 byte longer than the nested nag request content"
        );
        assert_eq!(
            content[0],
            GossipsubMsgKind::NagRequest as u8,
            "NagRequestExchange discriminator should be 0x04"
        );
        assert_eq!(
            &content[1..],
            &nag_content,
            "NagRequestExchange should append the nested nag request bytes unchanged"
        );
    }

    // Verifies GossipsubMsg::content_bytes() delegates to the unsigned message.
    #[test]
    fn gossipsub_msg_content_bytes_delegates_to_unsigned() {
        let keypair = test_keypair();
        let unsigned = UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx: 1,
            operator_idx: 2,
            operator_desc: test_payout_descriptor(),
        };

        let signed = unsigned.clone().sign_ed25519(&keypair);

        assert_eq!(
            signed.content_bytes(),
            unsigned.content_bytes(),
            "GossipsubMsg::content_bytes should return unsigned message content"
        );
    }

    // Verifies NagRequestPayload::DepositNonce serializes with correct byte layout.
    #[test]
    fn nag_payload_deposit_nonce_serializes_correctly() {
        let payload = NagRequestPayload::DepositNonce { deposit_idx: 42 };
        let content = payload.content_bytes();

        // Check structure: discriminator (1) + deposit_idx (4)
        assert_eq!(
            content.len(),
            1 + 4,
            "DepositNonce should be 5 bytes: discriminator (1) + deposit_idx (4)"
        );
        assert_eq!(
            content[0], 0x00,
            "DepositNonce discriminator should be 0x00"
        );
        assert_eq!(
            &content[1..5],
            &42u32.to_le_bytes(),
            "deposit_idx should be serialized as little-endian u32"
        );
    }

    // Verifies NagRequest serializes with correct byte layout.
    #[test]
    fn nag_request_serializes_correctly() {
        let recipient_bytes = vec![0xABu8; 32];
        let nag = NagRequest {
            recipient: P2POperatorPubKey::from(recipient_bytes.clone()),
            payload: NagRequestPayload::DepositNonce { deposit_idx: 42 },
        };
        let content = nag.content_bytes();

        // Check structure: recipient (32) + payload content_bytes (1 + 4)
        assert_eq!(
            content.len(),
            32 + 1 + 4,
            "NagRequest should be 37 bytes: recipient (32) + payload (5)"
        );
        assert_eq!(
            &content[0..32],
            &recipient_bytes[..],
            "First 32 bytes should be the recipient public key"
        );
        assert_eq!(
            content[32], 0x00,
            "Payload discriminator should be 0x00 for DepositNonce"
        );
        assert_eq!(
            &content[33..37],
            &42u32.to_le_bytes(),
            "deposit_idx should be serialized as little-endian u32"
        );
    }

    // Verifies graph nag payload bytes are stable and ordered as
    // [discriminator][operator][deposit].
    #[test]
    fn nag_payload_graph_content_bytes_stability() {
        let graph_data = NagRequestPayload::GraphData {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 2,
            },
        };
        let nonces = NagRequestPayload::GraphNonces {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 2,
            },
        };
        let partials = NagRequestPayload::GraphPartials {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 2,
            },
        };

        assert_eq!(
            graph_data.content_bytes(),
            vec![0x04, 1, 0, 0, 0, 2, 0, 0, 0],
            "GraphData must serialize as [0x04][operator_idx LE][deposit_idx LE]"
        );
        assert_eq!(
            nonces.content_bytes(),
            vec![0x05, 1, 0, 0, 0, 2, 0, 0, 0],
            "GraphNonces must serialize as [0x05][operator_idx LE][deposit_idx LE]"
        );
        assert_eq!(
            partials.content_bytes(),
            vec![0x06, 1, 0, 0, 0, 2, 0, 0, 0],
            "GraphPartials must serialize as [0x06][operator_idx LE][deposit_idx LE]"
        );
    }

    // Verifies unstaking nag payload bytes are stable and ordered as
    // [discriminator][operator_idx].
    #[test]
    fn nag_payload_unstaking_content_bytes_stability() {
        let data = NagRequestPayload::UnstakingData { operator_idx: 1 };
        let nonces = NagRequestPayload::UnstakingNonces { operator_idx: 1 };
        let partials = NagRequestPayload::UnstakingPartials { operator_idx: 1 };

        assert_eq!(
            data.content_bytes(),
            vec![0x07, 1, 0, 0, 0],
            "UnstakingData must serialize as [0x07][operator_idx LE]"
        );
        assert_eq!(
            nonces.content_bytes(),
            vec![0x08, 1, 0, 0, 0],
            "UnstakingNonces must serialize as [0x08][operator_idx LE]"
        );
        assert_eq!(
            partials.content_bytes(),
            vec![0x09, 1, 0, 0, 0],
            "UnstakingPartials must serialize as [0x09][operator_idx LE]"
        );
    }

    mod proptests {
        use proptest::prelude::*;
        use rkyv::{from_bytes, rancor::Error, to_bytes};

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            // Verifies rkyv serialization roundtrip for random MuSig2Nonce values.
            #[test]
            fn musig2_nonce_rkyv_roundtrip(nonce: MuSig2Nonce) {
                let bytes = to_bytes::<Error>(&nonce).expect("serialize");
                let recovered: MuSig2Nonce = from_bytes::<MuSig2Nonce, Error>(&bytes).expect("deserialize");
                // Compare content_bytes since MuSig2Nonce doesn't derive PartialEq
                prop_assert_eq!(nonce.content_bytes(), recovered.content_bytes());
            }

            // Verifies rkyv serialization roundtrip for random MuSig2Partial values.
            #[test]
            fn musig2_partial_rkyv_roundtrip(partial: MuSig2Partial) {
                let bytes = to_bytes::<Error>(&partial).expect("serialize");
                let recovered: MuSig2Partial = from_bytes::<MuSig2Partial, Error>(&bytes).expect("deserialize");
                // Compare content_bytes since MuSig2Partial doesn't derive PartialEq
                prop_assert_eq!(partial.content_bytes(), recovered.content_bytes());
            }

            // Verifies rkyv serialization roundtrip for random UnsignedGossipsubMsg values.
            #[test]
            fn unsigned_gossipsub_msg_rkyv_roundtrip(msg: UnsignedGossipsubMsg) {
                let bytes = to_bytes::<Error>(&msg).expect("serialize");
                let recovered: UnsignedGossipsubMsg = from_bytes::<UnsignedGossipsubMsg, Error>(&bytes).expect("deserialize");
                // Compare content since UnsignedGossipsubMsg doesn't derive PartialEq
                prop_assert_eq!(msg.content_bytes(), recovered.content_bytes());
            }

            // Verifies rkyv serialization roundtrip for random NagRequestPayload values.
            #[test]
            fn nag_request_payload_rkyv_roundtrip(payload: NagRequestPayload) {
                let bytes = to_bytes::<Error>(&payload).expect("serialize");
                let recovered: NagRequestPayload = from_bytes::<NagRequestPayload, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(payload, recovered);
            }

            // Verifies rkyv serialization roundtrip for random NagRequest values.
            #[test]
            fn nag_request_rkyv_roundtrip(nag: NagRequest) {
                let bytes = to_bytes::<Error>(&nag).expect("serialize");
                let recovered: NagRequest = from_bytes::<NagRequest, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(nag, recovered);
            }
        }
    }
}
