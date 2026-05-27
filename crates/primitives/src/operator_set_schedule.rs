//! Scheduled operator set primitive.

use std::{collections::BTreeSet, slice};

use bitcoin::XOnlyPublicKey;
use bitcoin_bosd::{Descriptor, DescriptorType};
use libp2p_identity::ed25519::PublicKey as LibP2pEdPublicKey;

use crate::types::{BitcoinBlockHeight, OperatorIdx, P2POperatorPubKey};

/// A scheduled operator table used to derive active operator sets by block height.
///
/// Operator indices and keys are globally unique within the schedule. Reusing an index for a later
/// activation window is rejected so that historical state-machine snapshots remain unambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSetSchedule {
    operators: Vec<ScheduledOperator>,
}

impl OperatorSetSchedule {
    /// Creates a validated operator schedule sorted by operator index.
    pub fn new(mut operators: Vec<ScheduledOperator>) -> Result<Self, OperatorSetScheduleError> {
        validate_operator_schedule(&operators)?;
        operators.sort_by_key(ScheduledOperator::index);
        Ok(Self { operators })
    }

    /// Returns the number of scheduled operators.
    pub const fn len(&self) -> usize {
        self.operators.len()
    }

    /// Returns `true` when there are no scheduled operators.
    pub const fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    /// Returns all scheduled operators in deterministic operator-index order.
    pub fn iter(&self) -> slice::Iter<'_, ScheduledOperator> {
        self.operators.iter()
    }

    /// Returns scheduled operators active at `height`.
    ///
    /// Active ranges are `[activation_height, deactivation_height)`. Operators without a
    /// `deactivation_height` remain active indefinitely after activation.
    pub fn active_at(
        &self,
        height: BitcoinBlockHeight,
    ) -> impl Iterator<Item = &ScheduledOperator> {
        self.operators
            .iter()
            .filter(move |operator| operator.is_active_at(height))
    }

    /// Returns the scheduled operator with `index`.
    pub fn get(&self, index: OperatorIdx) -> Option<&ScheduledOperator> {
        self.operators
            .binary_search_by_key(&index, ScheduledOperator::index)
            .ok()
            .map(|position| &self.operators[position])
    }
}

impl<'a> IntoIterator for &'a OperatorSetSchedule {
    type IntoIter = slice::Iter<'a, ScheduledOperator>;
    type Item = &'a ScheduledOperator;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A configured bridge operator and the height range in which it is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledOperator {
    /// Stable operator index used in state machines and peer resolution.
    index: OperatorIdx,

    /// Key used for MuSig2 signing in the bridge covenant.
    signing_key: XOnlyPublicKey,

    /// Key used for authenticated p2p communication.
    p2p_key: P2POperatorPubKey,

    /// The operator payout descriptor.
    payout_descriptor: Descriptor,

    /// First Bitcoin block height at which this operator is active.
    activation_height: BitcoinBlockHeight,

    /// First Bitcoin block height at which this operator is no longer active.
    deactivation_height: Option<BitcoinBlockHeight>,
}

impl ScheduledOperator {
    /// Creates a scheduled operator after validating its local invariants.
    pub fn new(
        index: OperatorIdx,
        signing_key: XOnlyPublicKey,
        p2p_key: P2POperatorPubKey,
        payout_descriptor: Descriptor,
        activation_height: BitcoinBlockHeight,
        deactivation_height: Option<BitcoinBlockHeight>,
    ) -> Result<Self, ScheduledOperatorError> {
        if let Some(deactivation_height) = deactivation_height {
            if deactivation_height <= activation_height {
                return Err(ScheduledOperatorError::InvalidActiveRange {
                    index,
                    activation_height,
                    deactivation_height,
                });
            }
        }

        if LibP2pEdPublicKey::try_from_bytes(p2p_key.as_ref()).is_err() {
            return Err(ScheduledOperatorError::InvalidP2pKey { index });
        }

        if payout_descriptor.type_tag() != DescriptorType::P2tr {
            return Err(ScheduledOperatorError::NonP2trPayoutDescriptor { index });
        }

        Ok(Self {
            index,
            signing_key,
            p2p_key,
            payout_descriptor,
            activation_height,
            deactivation_height,
        })
    }

    /// Returns the stable operator index.
    pub const fn index(&self) -> OperatorIdx {
        self.index
    }

    /// Returns the operator signing key.
    pub const fn signing_key(&self) -> XOnlyPublicKey {
        self.signing_key
    }

    /// Returns the p2p public key.
    pub const fn p2p_key(&self) -> &P2POperatorPubKey {
        &self.p2p_key
    }

    /// Returns the payout descriptor.
    pub const fn payout_descriptor(&self) -> &Descriptor {
        &self.payout_descriptor
    }

    /// Returns the activation height.
    pub const fn activation_height(&self) -> BitcoinBlockHeight {
        self.activation_height
    }

    /// Returns the optional deactivation height.
    pub const fn deactivation_height(&self) -> Option<BitcoinBlockHeight> {
        self.deactivation_height
    }

    /// Returns `true` iff the operator is active at `height`.
    pub fn is_active_at(&self, height: BitcoinBlockHeight) -> bool {
        height >= self.activation_height
            && self
                .deactivation_height
                .is_none_or(|deactivation_height| height < deactivation_height)
    }

    /// Returns the even-Y secp256k1 public key corresponding to the x-only signing key.
    pub fn signing_public_key(&self) -> secp256k1::PublicKey {
        self.signing_key.public_key(secp256k1::Parity::Even)
    }
}

/// Validation failures for [`ScheduledOperator`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduledOperatorError {
    /// The p2p key bytes are not a valid ed25519 public key.
    #[error("operator index {index} has an invalid p2p key")]
    InvalidP2pKey {
        /// The operator index with the invalid key.
        index: OperatorIdx,
    },
    /// The payout descriptor is not P2TR.
    #[error("operator index {index} must have a P2TR payout descriptor")]
    NonP2trPayoutDescriptor {
        /// The operator index with the invalid payout descriptor.
        index: OperatorIdx,
    },
    /// The optional deactivation height is not greater than the activation height.
    #[error(
        "operator index {index} has invalid active range: activation_height \
         {activation_height}, deactivation_height {deactivation_height}"
    )]
    InvalidActiveRange {
        /// The operator index with the invalid range.
        index: OperatorIdx,
        /// The configured activation height.
        activation_height: BitcoinBlockHeight,
        /// The configured deactivation height.
        deactivation_height: BitcoinBlockHeight,
    },
}

/// Validation failures for [`OperatorSetSchedule`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperatorSetScheduleError {
    /// An operator index appears more than once.
    #[error("duplicate operator index {index}")]
    DuplicateOperatorIndex {
        /// The duplicated operator index.
        index: OperatorIdx,
    },
    /// A signing key appears more than once.
    #[error("duplicate signing key for operator index {index}")]
    DuplicateSigningKey {
        /// The index of the operator that reused a signing key.
        index: OperatorIdx,
    },
    /// A p2p key appears more than once.
    #[error("duplicate p2p key for operator index {index}")]
    DuplicateP2pKey {
        /// The index of the operator that reused a p2p key.
        index: OperatorIdx,
    },
}

fn validate_operator_schedule(
    operators: &[ScheduledOperator],
) -> Result<(), OperatorSetScheduleError> {
    let mut indices = BTreeSet::new();
    let mut signing_keys = BTreeSet::new();
    let mut p2p_keys = BTreeSet::new();

    for operator in operators {
        if !indices.insert(operator.index()) {
            return Err(OperatorSetScheduleError::DuplicateOperatorIndex {
                index: operator.index(),
            });
        }

        if !signing_keys.insert(operator.signing_key()) {
            return Err(OperatorSetScheduleError::DuplicateSigningKey {
                index: operator.index(),
            });
        }

        if !p2p_keys.insert(operator.p2p_key().clone()) {
            return Err(OperatorSetScheduleError::DuplicateP2pKey {
                index: operator.index(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin_bosd::{Descriptor, DescriptorType};

    use super::*;

    const XONLY_KEY_1: &str = "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d";
    const XONLY_KEY_2: &str = "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4";
    const P2P_KEY_1: &str = "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5";
    const P2P_KEY_2: &str = "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d";

    #[test]
    fn active_range_is_activation_inclusive_and_deactivation_exclusive() {
        let schedule = OperatorSetSchedule::new(vec![
            scheduled_operator(0, XONLY_KEY_1, P2P_KEY_1, 101, None),
            scheduled_operator(1, XONLY_KEY_2, P2P_KEY_2, 200, Some(300)),
        ])
        .expect("schedule must be valid");

        assert_eq!(schedule.active_at(100).count(), 0);
        assert_eq!(schedule.active_at(101).count(), 1);
        assert_eq!(schedule.active_at(200).count(), 2);
        assert_eq!(schedule.active_at(300).count(), 1);
    }

    #[test]
    fn duplicate_operator_indices_are_rejected() {
        let err = OperatorSetSchedule::new(vec![
            scheduled_operator(0, XONLY_KEY_1, P2P_KEY_1, 101, None),
            scheduled_operator(0, XONLY_KEY_2, P2P_KEY_2, 200, None),
        ])
        .expect_err("duplicate index must fail validation");

        assert!(matches!(
            err,
            OperatorSetScheduleError::DuplicateOperatorIndex { index: 0 }
        ));
    }

    #[test]
    fn duplicate_operator_keys_are_rejected() {
        let duplicate_signing_key = OperatorSetSchedule::new(vec![
            scheduled_operator(0, XONLY_KEY_1, P2P_KEY_1, 101, None),
            scheduled_operator(1, XONLY_KEY_1, P2P_KEY_2, 101, None),
        ])
        .expect_err("duplicate signing key must fail validation");
        assert!(matches!(
            duplicate_signing_key,
            OperatorSetScheduleError::DuplicateSigningKey { index: 1 }
        ));

        let duplicate_p2p_key = OperatorSetSchedule::new(vec![
            scheduled_operator(0, XONLY_KEY_1, P2P_KEY_1, 101, None),
            scheduled_operator(1, XONLY_KEY_2, P2P_KEY_1, 101, None),
        ])
        .expect_err("duplicate p2p key must fail validation");
        assert!(matches!(
            duplicate_p2p_key,
            OperatorSetScheduleError::DuplicateP2pKey { index: 1 }
        ));
    }

    #[test]
    fn invalid_operator_active_range_is_rejected() {
        let err = ScheduledOperator::new(
            0,
            XOnlyPublicKey::from_str(XONLY_KEY_1).unwrap(),
            P2POperatorPubKey::from(hex::decode(P2P_KEY_1).unwrap()),
            p2tr_descriptor(XONLY_KEY_1),
            101,
            Some(101),
        )
        .expect_err("deactivation height must be greater than activation height");

        assert!(matches!(
            err,
            ScheduledOperatorError::InvalidActiveRange {
                index: 0,
                activation_height: 101,
                deactivation_height: 101,
            }
        ));
    }

    #[test]
    fn invalid_operator_p2p_key_is_rejected() {
        let err = ScheduledOperator::new(
            0,
            XOnlyPublicKey::from_str(XONLY_KEY_1).unwrap(),
            P2POperatorPubKey::from(vec![0; 31]),
            p2tr_descriptor(XONLY_KEY_1),
            101,
            None,
        )
        .expect_err("p2p key must be valid ed25519 public key bytes");

        assert!(matches!(
            err,
            ScheduledOperatorError::InvalidP2pKey { index: 0 }
        ));
    }

    #[test]
    fn non_p2tr_operator_payout_descriptor_is_rejected() {
        let err = ScheduledOperator::new(
            0,
            XOnlyPublicKey::from_str(XONLY_KEY_1).unwrap(),
            P2POperatorPubKey::from(hex::decode(P2P_KEY_1).unwrap()),
            Descriptor::new_op_return(&[1, 2, 3]).expect("valid descriptor"),
            101,
            None,
        )
        .expect_err("payout descriptor must be p2tr");

        assert!(matches!(
            err,
            ScheduledOperatorError::NonP2trPayoutDescriptor { index: 0 }
        ));
    }

    fn scheduled_operator(
        index: OperatorIdx,
        signing_key: &str,
        p2p_key: &str,
        activation_height: BitcoinBlockHeight,
        deactivation_height: Option<BitcoinBlockHeight>,
    ) -> ScheduledOperator {
        ScheduledOperator::new(
            index,
            XOnlyPublicKey::from_str(signing_key).unwrap(),
            P2POperatorPubKey::from(hex::decode(p2p_key).unwrap()),
            p2tr_descriptor(signing_key),
            activation_height,
            deactivation_height,
        )
        .expect("scheduled operator must be valid")
    }

    fn p2tr_descriptor(xonly_hex: &str) -> Descriptor {
        let pk_bytes: [u8; 32] = hex::decode(xonly_hex)
            .expect("valid hex")
            .try_into()
            .expect("x-only public key must be 32 bytes");

        let descriptor = Descriptor::new_p2tr(&pk_bytes).expect("valid p2tr descriptor");
        assert_eq!(descriptor.type_tag(), DescriptorType::P2tr);
        descriptor
    }
}
