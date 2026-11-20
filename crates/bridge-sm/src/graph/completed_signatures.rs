//! Backward-compatible encoding of optional counterproof signatures.
//!
//! Postcard records retain the original fixed array of length-prefixed signatures. An empty
//! first byte string represents absence; a present signature always has 64 bytes. Old readers
//! reject absent signatures rather than interpreting them as NACK material.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_big_array::{Array, BigArray};
use strata_mosaic_client_api::types::{COUNTERPROOF_N_DATA, CompletedSignatures, Signature};

pub(super) fn serialize<S: Serializer>(
    signatures: &Option<CompletedSignatures>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        signatures.as_ref().map(|s| Array(*s)).serialize(serializer)
    } else if let Some(signatures) = signatures {
        BigArray::serialize(signatures, serializer)
    } else {
        serializer.serialize_bytes(&[])
    }
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CompletedSignatures>, D::Error> {
    if deserializer.is_human_readable() {
        return Option::<Array<Signature, COUNTERPROOF_N_DATA>>::deserialize(deserializer)
            .map(|signatures| signatures.map(|s| s.0));
    }

    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = Option<CompletedSignatures>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("counterproof signatures or an empty byte string")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let first: Vec<u8> = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            if first.is_empty() {
                return Ok(None);
            }
            let first = Signature::from_slice(&first).map_err(de::Error::custom)?;
            let mut signatures = [first; COUNTERPROOF_N_DATA];
            for (idx, signature) in signatures.iter_mut().enumerate().skip(1) {
                *signature = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(idx, &self))?;
            }
            Ok(Some(signatures))
        }
    }

    deserializer.deserialize_tuple(COUNTERPROOF_N_DATA, Visitor)
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;

    use super::*;
    use crate::graph::{state::CounterproofData, tests::test_completed_signatures};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct LegacyCounterproofData {
        txid: Txid,
        conf_height: u64,
        #[serde(with = "BigArray")]
        completed_signatures: CompletedSignatures,
    }

    #[test]
    fn existing_records_keep_their_encoding() {
        let legacy = LegacyCounterproofData {
            txid: "11".repeat(32).parse().unwrap(),
            conf_height: 123,
            completed_signatures: test_completed_signatures(),
        };
        let bytes = postcard::to_allocvec(&legacy).unwrap();
        let data: CounterproofData = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(data.completed_signatures, Some(legacy.completed_signatures));
        assert_eq!(postcard::to_allocvec(&data).unwrap(), bytes);
        assert_eq!(
            postcard::from_bytes::<LegacyCounterproofData>(&bytes).unwrap(),
            legacy
        );
    }

    #[test]
    fn optional_records_preserve_following_fields() {
        let records: Vec<_> = [None, Some(test_completed_signatures()), None]
            .into_iter()
            .map(|completed_signatures| CounterproofData {
                txid: "22".repeat(32).parse().unwrap(),
                conf_height: 456,
                completed_signatures,
            })
            .collect();
        let expected = (records, 987u64);
        let bytes = postcard::to_allocvec(&expected).unwrap();
        let actual: (Vec<CounterproofData>, u64) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(actual, expected);
        let absent = postcard::to_allocvec(&expected.0[0]).unwrap();
        assert!(postcard::from_bytes::<LegacyCounterproofData>(&absent).is_err());
    }

    #[test]
    fn truncated_records_are_not_treated_as_absent() {
        let data = CounterproofData {
            txid: "33".repeat(32).parse().unwrap(),
            conf_height: 789,
            completed_signatures: Some(test_completed_signatures()),
        };
        let bytes = postcard::to_allocvec(&data).unwrap();
        for len in 0..bytes.len() {
            assert!(postcard::from_bytes::<CounterproofData>(&bytes[..len]).is_err());
        }
    }
}
