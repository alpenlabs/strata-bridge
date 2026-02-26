//! Message types for P2P communication with compile-time type safety.

use std::fmt;

use bitcoin::hashes::Hash;
use libp2p_identity::ed25519;
use proptest_derive::Arbitrary;
use rkyv::{Archive, Deserialize, Serialize};
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

use crate::{
    ClaimInput, GraphIdx, P2POperatorPubKey, PartialSignature, PayoutDescriptor, PubNonce,
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
    /// Multiple nonces for graph signing (one per graph transaction).
    Graph {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,
        /// One nonce per transaction in the graph.
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
    /// Multiple partials for graph signing (one per graph transaction).
    Graph {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,
        /// One partial signature per transaction in the graph.
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
        }
    }
}

/// Unsigned gossipsub messages.
#[derive(Clone, Archive, Serialize, Deserialize, Arbitrary)]
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

    /// Graph data exchange.
    GraphDataExchange {
        /// The graph index to identify the instance of the graph.
        graph_idx: GraphIdx,

        /// The input to the claim transaction.
        claim_input: ClaimInput,
    },

    /// MuSig2 nonces exchange.
    Musig2NoncesExchange(MuSig2Nonce),

    /// MuSig2 partial signatures exchange.
    Musig2SignaturesExchange(MuSig2Partial),
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
                claim_input,
            } => {
                let outpoint = claim_input.inner();
                buf.push(GossipsubMsgKind::GraphDataExchange as u8);
                buf.extend(graph_idx.deposit.to_le_bytes());
                buf.extend(graph_idx.operator.to_le_bytes());
                buf.extend(outpoint.txid.to_raw_hash().to_byte_array()); // txid
                buf.extend(outpoint.vout.to_le_bytes()); // vout
            }
            Self::Musig2NoncesExchange(nonce) => {
                buf.push(GossipsubMsgKind::Musig2Nonces as u8);
                buf.extend(nonce.content_bytes());
            }
            Self::Musig2SignaturesExchange(partial) => {
                buf.push(GossipsubMsgKind::Musig2Signatures as u8);
                buf.extend(partial.content_bytes());
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
                claim_input,
            } => {
                write!(
                    f,
                    "GraphDataExchange(graph_idx: {:?}, claim_input: {:?})",
                    graph_idx, claim_input
                )
            }
            Self::Musig2NoncesExchange(nonce) => {
                write!(f, "Musig2NoncesExchange({nonce:?})")
            }
            Self::Musig2SignaturesExchange(partial) => {
                write!(f, "Musig2SignaturesExchange({partial:?})")
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
    use libp2p_identity::ed25519::Keypair;
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_test_utils::musig2::{generate_partial_signature, generate_pubnonce};

    use super::*;
    use crate::{PartialSignature, PayoutDescriptor, PubNonce};

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

    // ==================== Domain Separation Tests ====================

    // Verifies MuSig2Nonce::Deposit uses discriminator 0x00.
    #[test]
    fn musig2_nonce_deposit_has_correct_prefix() {
        let nonce = MuSig2Nonce::Deposit {
            deposit_idx: 42,
            nonce: test_pubnonce(),
        };
        let content = nonce.content_bytes();
        assert_eq!(content[0], 0x00, "Deposit should have prefix 0x00");
    }

    // Verifies MuSig2Nonce::Payout uses discriminator 0x01.
    #[test]
    fn musig2_nonce_payout_has_correct_prefix() {
        let nonce = MuSig2Nonce::Payout {
            deposit_idx: 42,
            nonce: test_pubnonce(),
        };
        let content = nonce.content_bytes();
        assert_eq!(content[0], 0x01, "Payout should have prefix 0x01");
    }

    // Verifies MuSig2Nonce::Graph uses discriminator 0x02.
    #[test]
    fn musig2_nonce_graph_has_correct_prefix() {
        let nonce = MuSig2Nonce::Graph {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 2,
            },
            nonces: vec![test_pubnonce()],
        };
        let content = nonce.content_bytes();
        assert_eq!(content[0], 0x02, "Graph should have prefix 0x02");
    }

    // Verifies MuSig2Partial::Deposit uses discriminator 0x00.
    #[test]
    fn musig2_partial_deposit_has_correct_prefix() {
        let partial = MuSig2Partial::Deposit {
            deposit_idx: 42,
            partial: test_partial_signature(),
        };
        let content = partial.content_bytes();
        assert_eq!(content[0], 0x00, "Deposit should have prefix 0x00");
    }

    // Verifies MuSig2Partial::Payout uses discriminator 0x01.
    #[test]
    fn musig2_partial_payout_has_correct_prefix() {
        let partial = MuSig2Partial::Payout {
            deposit_idx: 42,
            partial: test_partial_signature(),
        };
        let content = partial.content_bytes();
        assert_eq!(content[0], 0x01, "Payout should have prefix 0x01");
    }

    // Verifies MuSig2Partial::Graph uses discriminator 0x02.
    #[test]
    fn musig2_partial_graph_has_correct_prefix() {
        let partial = MuSig2Partial::Graph {
            graph_idx: GraphIdx {
                operator: 1,
                deposit: 2,
            },
            partials: vec![test_partial_signature()],
        };
        let content = partial.content_bytes();
        assert_eq!(content[0], 0x02, "Graph should have prefix 0x02");
    }

    // Verifies PayoutDescriptorExchange uses discriminator 0x00.
    #[test]
    fn unsigned_msg_payout_descriptor_has_correct_prefix() {
        let msg = UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx: 1,
            operator_idx: 2,
            operator_desc: test_payout_descriptor(),
        };
        let content = msg.content_bytes();
        assert_eq!(
            content[0], 0x00,
            "PayoutDescriptorExchange should have prefix 0x00"
        );
    }

    // Verifies Musig2NoncesExchange uses discriminator 0x01.
    #[test]
    fn unsigned_msg_nonces_has_correct_prefix() {
        let msg = UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Deposit {
            deposit_idx: 1,
            nonce: test_pubnonce(),
        });
        let content = msg.content_bytes();
        assert_eq!(
            content[0], 0x01,
            "Musig2NoncesExchange should have prefix 0x01"
        );
    }

    // Verifies Musig2SignaturesExchange uses discriminator 0x02.
    #[test]
    fn unsigned_msg_signatures_has_correct_prefix() {
        let msg = UnsignedGossipsubMsg::Musig2SignaturesExchange(MuSig2Partial::Deposit {
            deposit_idx: 1,
            partial: test_partial_signature(),
        });
        let content = msg.content_bytes();
        assert_eq!(
            content[0], 0x02,
            "Musig2SignaturesExchange should have prefix 0x02"
        );
    }

    // ==================== Content Serialization Tests ====================

    // Verifies MuSig2Nonce::Deposit serializes with correct byte layout.
    #[test]
    fn musig2_nonce_deposit_serializes_correctly() {
        let nonce = MuSig2Nonce::Deposit {
            deposit_idx: 42,
            nonce: test_pubnonce(),
        };
        let content = nonce.content_bytes();

        assert_eq!(content.len(), 1 + 4 + 66);
        assert_eq!(content[0], 0x00);
        assert_eq!(&content[1..5], &42u32.to_le_bytes());
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
        assert_eq!(content.len(), 1 + 4 + 4 + 3 * 66);
        assert_eq!(content[0], 0x02);
        assert_eq!(&content[1..5], &10u32.to_le_bytes()); // operator_idx
        assert_eq!(&content[5..9], &20u32.to_le_bytes()); // deposit_idx
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
        assert_eq!(content.len(), 1 + 4 + 4 + 2 * 32);
        assert_eq!(content[0], 0x02);
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
        assert_eq!(content.len(), 1 + 4 + 4);
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
        assert_eq!(content.len(), 1 + 4 + 4);
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
        }
    }
}
