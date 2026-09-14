//! Covenant identity for current, prepared, and historical operator sets.

use std::fmt;

use bitcoin::XOnlyPublicKey;
use musig2::{errors::KeyAggError, KeyAggContext};
use serde::{Deserialize, Serialize};

use crate::{operator_table::OperatorTable, types::BitcoinBlockHeight};

/// The signing authority and admin activation boundary of a covenant.
///
/// Automatic exits change the aggregate key but retain the last effective admin-change height.
/// An effective admin addition or removal changes that height even if all surviving operators
/// registered earlier. Exit block heights and hashes belong to transition provenance separately.
///
/// Equality does not establish equal operator-index mappings, P2P keys, payout descriptors, or
/// protocol settings. Validate those against the exact target context before reusing prepared
/// stakes; [`OperatorTable::has_same_membership`] compares the indexed signing and P2P keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CovenantId {
    /// The untweaked aggregate of signing keys in canonical operator-index order.
    pub aggregate_pubkey: XOnlyPublicKey,
    /// The effective height of the most recent admin membership change, or initial activation.
    pub activation_height: BitcoinBlockHeight,
}

impl CovenantId {
    /// Derives an identity from exact membership and its explicit admin activation boundary.
    ///
    /// Accepts both participant and public tables and does not consult local stake state or the
    /// current chain height. A planned covenant can therefore be identified before activation.
    /// The caller must retain the existing admin height for automatic exits rather than using
    /// the exit height or recomputing it from surviving registrations.
    ///
    /// Returns an error for empty membership or an invalid aggregate key.
    pub fn from_operator_table<Pov>(
        operators: &OperatorTable<Pov>,
        activation_height: BitcoinBlockHeight,
    ) -> Result<Self, KeyAggError> {
        // KeyAggContext panics on empty input; recovered tables can bypass constructor checks.
        if operators.cardinality() == 0 {
            return Err(KeyAggError);
        }
        let aggregate: secp256k1::PublicKey =
            KeyAggContext::new(operators.btc_keys())?.aggregated_pubkey();
        Ok(Self {
            aggregate_pubkey: aggregate.x_only_public_key().0,
            activation_height,
        })
    }

    /// Encodes the 32-byte x-only key followed by the eight-byte big-endian activation height.
    pub fn to_bytes(self) -> [u8; 40] {
        let mut bytes = [0; 40];
        bytes[..32].copy_from_slice(&self.aggregate_pubkey.serialize());
        bytes[32..].copy_from_slice(&self.activation_height.to_be_bytes());
        bytes
    }

    /// Decodes the fixed-width representation, rejecting invalid x-only public keys.
    pub fn from_bytes(bytes: [u8; 40]) -> Result<Self, secp256k1::Error> {
        let aggregate_pubkey = XOnlyPublicKey::from_slice(&bytes[..32])?;
        let mut height = [0; 8];
        height.copy_from_slice(&bytes[32..]);
        Ok(Self {
            aggregate_pubkey,
            activation_height: BitcoinBlockHeight::from_be_bytes(height),
        })
    }
}

impl fmt::Display for CovenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.aggregate_pubkey, self.activation_height)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;

    use super::*;
    use crate::{
        operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
        operator_table::PublicOperatorTable,
        types::P2POperatorPubKey,
    };

    const SIGNING_KEYS: [&str; 3] = [
        "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d",
        "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4",
        "a4d869ccd09c470f8f86d3f1b0997fa2695933aaea001875b9db145ae9c1f4ba",
    ];
    const P2P_KEYS: [&str; 3] = [
        "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5",
        "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d",
        "aeabd3a377c160590a0927bca0cb315eaebf5acc87476fbb317c6260b6f123c6",
    ];

    fn registrations() -> Vec<ScheduledOperator> {
        (0..3)
            .map(|i| {
                let key: XOnlyPublicKey = SIGNING_KEYS[i].parse().unwrap();
                ScheduledOperator::new(
                    i as u32,
                    key,
                    P2POperatorPubKey::from(hex::decode(P2P_KEYS[i]).unwrap()),
                    Descriptor::new_p2tr(&key.serialize()).unwrap(),
                    if i == 2 { 200 } else { 100 },
                    if i == 2 { Some(300) } else { None },
                )
                .unwrap()
            })
            .collect()
    }

    fn table_at(
        registrations: Vec<ScheduledOperator>,
        height: BitcoinBlockHeight,
    ) -> PublicOperatorTable {
        let schedule = OperatorSetSchedule::new(registrations).unwrap();
        PublicOperatorTable::from_entries(
            schedule
                .active_at(height)
                .map(|op| (op.index(), op.p2p_key().clone(), op.covenant_public_key()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn identity_and_serialization_are_independent_of_file_order_and_local_membership() {
        let public = table_at(registrations(), 200);
        let mut shuffled = registrations();
        shuffled.reverse();
        let other = table_at(shuffled, 200);
        let expected = CovenantId::from_operator_table(&public, 200).unwrap();
        let first_participant = public.clone().with_pov(0).unwrap();
        let last_participant = public.clone().with_pov(2).unwrap();

        for id in [
            CovenantId::from_operator_table(&other, 200).unwrap(),
            CovenantId::from_operator_table(&first_participant, 200).unwrap(),
            CovenantId::from_operator_table(&last_participant, 200).unwrap(),
        ] {
            assert_eq!(id, expected);
            assert_eq!(id.to_bytes(), expected.to_bytes());
            assert_eq!(
                serde_json::to_string(&id).unwrap(),
                serde_json::to_string(&expected).unwrap()
            );
        }
        assert_eq!(
            expected.aggregate_pubkey,
            public.aggregated_btc_key().x_only_public_key().0
        );
    }

    #[test]
    fn recovered_empty_membership_cannot_produce_a_covenant() {
        let empty: PublicOperatorTable = serde_json::from_value(serde_json::json!({
            "pov": null, "idx_key": {}, "p2p_key": {}, "btc_key": {},
        }))
        .unwrap();
        assert_eq!(
            CovenantId::from_operator_table(&empty, 200),
            Err(KeyAggError)
        );
    }

    #[test]
    fn encoding_and_formatting_include_key_and_admin_activation_height() {
        let id = CovenantId {
            aggregate_pubkey: SIGNING_KEYS[0].parse().unwrap(),
            activation_height: 0x0102_0304_0506_0708,
        };
        let expected = format!("{}0102030405060708", SIGNING_KEYS[0]);
        assert_eq!(hex::encode(id.to_bytes()), expected);
        assert_eq!(CovenantId::from_bytes(id.to_bytes()).unwrap(), id);
        assert_eq!(
            id.to_string(),
            format!("{}@72623859790382856", SIGNING_KEYS[0])
        );
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"aggregate_pubkey":"{}","activation_height":72623859790382856}}"#,
                SIGNING_KEYS[0]
            )
        );
        assert_eq!(serde_json::from_str::<CovenantId>(&json).unwrap(), id);

        for height in [0, u64::MAX] {
            let boundary = CovenantId {
                activation_height: height,
                ..id
            };
            assert_eq!(
                CovenantId::from_bytes(boundary.to_bytes()).unwrap(),
                boundary
            );
        }
        assert!(CovenantId::from_bytes([0xff; 40]).is_err());
    }

    #[test]
    fn planned_identity_requires_matching_final_membership_and_activation_height() {
        let prepared_members = table_at(registrations(), 200);
        let planned = CovenantId::from_operator_table(&prepared_members, 200).unwrap();
        let final_members = table_at(registrations(), 200);
        let actual = CovenantId::from_operator_table(&final_members, 200).unwrap();
        assert_eq!(actual, planned);
        assert!(prepared_members.has_same_membership(&final_members));

        let delayed = CovenantId::from_operator_table(&final_members, 201).unwrap();
        assert_eq!(delayed.aggregate_pubkey, planned.aggregate_pubkey);
        assert_ne!(delayed, planned);
        assert_ne!(delayed.to_bytes(), planned.to_bytes());

        let after_exit = table_at(registrations(), 300);
        let successor = CovenantId::from_operator_table(&after_exit, 200).unwrap();
        assert_ne!(successor, planned);
        assert!(!prepared_members.has_same_membership(&after_exit));
    }

    #[test]
    fn automatic_exit_retains_admin_height_while_admin_removal_advances_it() {
        let previous_members = table_at(registrations(), 200);
        let previous = CovenantId::from_operator_table(&previous_members, 200).unwrap();
        let surviving_members = table_at(registrations(), 300);

        // An automatic exit at height 250 keeps the admin boundary at 200. The source block
        // belongs to transition provenance, not the covenant identity.
        let automatic =
            CovenantId::from_operator_table(&surviving_members, previous.activation_height)
                .unwrap();
        let admin = CovenantId::from_operator_table(&surviving_members, 300).unwrap();

        assert_ne!(automatic.aggregate_pubkey, previous.aggregate_pubkey);
        assert_eq!(automatic.activation_height, 200);
        assert_eq!(admin.activation_height, 300);
        assert_eq!(automatic.aggregate_pubkey, admin.aggregate_pubkey);
        assert_ne!(automatic, admin);
        assert!(registrations()
            .iter()
            .filter(|op| surviving_members.contains_idx(&op.index()))
            .all(|op| op.activation_height() == 100));
    }

    #[test]
    fn equal_ids_do_not_establish_equal_indexed_membership_or_payouts() {
        let members = table_at(registrations(), 200);
        let id = CovenantId::from_operator_table(&members, 200).unwrap();
        let remapped = PublicOperatorTable::from_entries(
            members
                .operator_idxs()
                .into_iter()
                .map(|index| {
                    (
                        index + 10,
                        members.idx_to_p2p_key(&index).unwrap().clone(),
                        members.idx_to_btc_key(&index).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(CovenantId::from_operator_table(&remapped, 200).unwrap(), id);
        assert!(!members.has_same_membership(&remapped));

        let mut changed_payout = registrations();
        let original = &changed_payout[0];
        changed_payout[0] = ScheduledOperator::new(
            original.index(),
            original.covenant_key(),
            original.p2p_key().clone(),
            changed_payout[1].payout_descriptor().clone(),
            original.activation_height(),
            original.deactivation_height(),
        )
        .unwrap();
        assert_ne!(changed_payout, registrations());
        let same_keys = table_at(changed_payout, 200);
        assert!(members.has_same_membership(&same_keys));
        assert_eq!(
            CovenantId::from_operator_table(&same_keys, 200).unwrap(),
            id
        );
    }
}
