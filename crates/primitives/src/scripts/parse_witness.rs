//! Scripts for parsing witness stacks.

use bitvm::{
    chunk::api::Signatures as g16Signatures,
    signatures::wots_api::{wots256, wots_hash},
    treepp::*,
};

use crate::{
    constants::*,
    errors::{ParseError, ParseResult},
};

/// Parses a set of WOTS hash signatures from a script.
pub fn parse_wots_hash_signatures<const N_SIGS: usize>(
    script: Script,
) -> ParseResult<[wots_hash::Signature; N_SIGS]> {
    let res = execute_script(script.clone());
    std::array::try_from_fn(|i| {
        std::array::try_from_fn(|j| {
            let k = 2 * j + i * 2 * wots_hash::N_DIGITS as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            Ok::<_, ParseError>((
                preimage
                    .try_into()
                    .map_err(|_| ParseError::InvalidWitness("wots_hash".to_string()))?,
                digit,
            ))
        })
    })
}

/// Parses a set of WOTS 256-bit signatures from a script.
pub fn parse_wots256_signatures<const N_SIGS: usize>(
    script: Script,
) -> ParseResult<[wots256::Signature; N_SIGS]> {
    let res = execute_script(script.clone());
    std::array::try_from_fn(|i| {
        std::array::try_from_fn(|j| {
            let k = 2 * j + i * 2 * wots256::N_DIGITS as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };
            Ok::<_, ParseError>((
                preimage
                    .try_into()
                    .map_err(|_| ParseError::InvalidWitness("wots256".to_string()))?,
                digit,
            ))
        })
    })
}

/// Parses the witness stack for an assertion.
pub fn parse_assertion_witnesses(
    witness256_batch1: [Script; NUM_FIELD_CONNECTORS_BATCH_1],
    witness256_batch2: [Script; NUM_FIELD_CONNECTORS_BATCH_2],
    witness_hash_batch1: [Script; NUM_HASH_CONNECTORS_BATCH_1],
    witness_hash_batch2: [Script; NUM_HASH_CONNECTORS_BATCH_2],
) -> ParseResult<g16Signatures> {
    let mut w256 = Vec::with_capacity(NUM_FIELD_CONNECTORS_BATCH_1);
    for witness in witness256_batch1.into_iter() {
        w256.push(parse_wots256_signatures::<
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1,
        >(witness)?);
    }

    let mut w256 = w256.into_iter().flatten().collect::<Vec<_>>();

    for witness in witness256_batch2.into_iter() {
        w256.extend(parse_wots256_signatures::<
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2,
        >(witness)?);
    }

    let mut w_hash = Vec::with_capacity(NUM_HASH_CONNECTORS_BATCH_1);
    for witness in witness_hash_batch1.into_iter() {
        w_hash.push(parse_wots_hash_signatures::<
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
        >(witness)?);
    }

    let mut w_hash = w_hash.into_iter().flatten().collect::<Vec<_>>();

    for witness in witness_hash_batch2.into_iter() {
        w_hash.extend(parse_wots_hash_signatures::<
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
        >(witness)?);
    }

    Ok((
        Box::new([w256[0]]), // proof public input
        Box::new(w256[1..].try_into().unwrap()),
        Box::new(w_hash.try_into().unwrap()),
    ))
}

#[cfg(test)]
mod tests {
    use bitvm::{
        signatures::wots_api::{
            wots256::{self, MSG_LEN},
            wots_hash, SignatureImpl, HASH_LEN,
        },
        treepp::*,
    };

    use super::*;

    fn create_message<const N_BYTES: usize>(i: usize) -> [u8; N_BYTES] {
        [i as u8; N_BYTES]
    }

    #[test]
    fn test_wots256_signatures_from_witness() {
        const N_SIGS: usize = 5;

        let secrets: [String; N_SIGS] = std::array::from_fn(|i| format!("{:04x}", i));

        let signatures: [_; N_SIGS] = std::array::from_fn(|i| {
            wots256::get_signature(&secrets[i], &create_message::<{ MSG_LEN as usize }>(i))
        });

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots256::get_signature(&secrets[i], &create_message::<{ MSG_LEN as usize }>(i)).to_script() }
            }
        };
        let parsed_signatures = parse_wots256_signatures::<N_SIGS>(signatures_script);

        assert!(parsed_signatures.is_ok_and(|sigs| sigs == signatures));
    }

    #[test]
    fn test_wots_hash_signatures_from_witness() {
        const N_SIGS: usize = 11;

        let secrets: [String; N_SIGS] = std::array::from_fn(|i| format!("{:04x}", i));

        let signatures: [_; N_SIGS] = std::array::from_fn(|i| {
            wots_hash::get_signature(&secrets[i], &create_message::<{ HASH_LEN as usize }>(i))
        });

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots_hash::get_signature(&secrets[i], &create_message::<{ HASH_LEN as usize }>(i)).to_script() }
            }
        };
        let parsed_signatures = parse_wots_hash_signatures::<N_SIGS>(signatures_script);

        assert!(parsed_signatures.is_ok_and(|sigs| sigs == signatures));
    }
}
