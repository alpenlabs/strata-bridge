//! Scripts for parsing witness stacks.

use std::array;

use bitvm::{
    signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256},
    treepp::*,
};

use crate::{
    constants::*,
    errors::{ParseError, ParseResult},
    wots::BitVmG16Sigs,
};

/// Parses a set of WOTS hash signatures from a script.
pub fn parse_wots_hash_signatures<const N_SIGS: usize>(
    script: Script,
) -> ParseResult<[<wots_hash as Wots>::Signature; N_SIGS]> {
    let res = execute_script(script.clone());
    array::try_from_fn(|i| {
        array::try_from_fn(|j| {
            let k = 2 * j + i * 2 * wots_hash::TOTAL_DIGIT_LEN as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };

            let mut sig = Vec::new();
            sig.extend_from_slice(&preimage);
            sig.push(digit);

            sig.try_into()
                .map_err(|_| ParseError::InvalidWitness("wots_hash".to_string()))
        })
    })
}

/// Parses a set of WOTS 256-bit signatures from a script.
pub fn parse_wots256_signatures<const N_SIGS: usize>(
    script: Script,
) -> ParseResult<[<wots256 as Wots>::Signature; N_SIGS]> {
    let res = execute_script(script.clone());
    array::try_from_fn(|i| {
        array::try_from_fn(|j| {
            let k = 2 * j + i * 2 * wots256::TOTAL_DIGIT_LEN as usize;
            let preimage = res.final_stack.get(k);
            let digit = res.final_stack.get(k + 1);
            let digit = if digit.is_empty() { 0u8 } else { digit[0] };

            let mut sig = Vec::new();
            sig.extend_from_slice(&preimage);
            sig.push(digit);

            sig.try_into()
                .map_err(|_| ParseError::InvalidWitness("wots256".to_string()))
        })
    })
}

/// Parses the witness stack for an assertion.
pub fn parse_assertion_witnesses(
    witness256_batch1: [Script; NUM_FIELD_CONNECTORS_BATCH_1],
    witness256_batch2: [Script; NUM_FIELD_CONNECTORS_BATCH_2],
    witness_hash_batch1: [Script; NUM_HASH_CONNECTORS_BATCH_1],
    witness_hash_batch2: [Script; NUM_HASH_CONNECTORS_BATCH_2],
) -> ParseResult<BitVmG16Sigs> {
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
        signatures::{Wots16 as wots_hash, Wots32 as wots256, HASH_LEN},
        treepp::*,
    };

    use super::*;

    fn create_message<const N_BYTES: usize>(i: usize) -> [u8; N_BYTES] {
        [i as u8; N_BYTES]
    }

    #[test]
    fn test_wots256_signatures_from_witness() {
        const N_SIGS: usize = 5;

        let secrets: [Vec<u8>; N_SIGS] = array::from_fn(|i| i.to_be_bytes().to_vec());
        const MSG_LEN: usize = wots256::MSG_BYTE_LEN as usize;

        let signatures: [_; N_SIGS] =
            array::from_fn(|i| wots256::sign(&secrets[i], &create_message::<{ MSG_LEN }>(i)));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots256::signature_to_raw_witness(&signatures[i]) }
            }
        };
        let parsed_signatures = parse_wots256_signatures::<N_SIGS>(signatures_script);

        assert!(parsed_signatures.is_ok_and(|sigs| sigs == signatures));
    }

    #[test]
    fn test_wots_hash_signatures_from_witness() {
        const N_SIGS: usize = 11;

        let secrets: [Vec<u8>; N_SIGS] = array::from_fn(|i| i.to_be_bytes().to_vec());

        let signatures: [_; N_SIGS] =
            array::from_fn(|i| wots_hash::sign(&secrets[i], &create_message::<HASH_LEN>(i)));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots_hash::signature_to_raw_witness(&signatures[i]) }
            }
        };
        let parsed_signatures = parse_wots_hash_signatures::<N_SIGS>(signatures_script);

        assert!(parsed_signatures.is_ok_and(|sigs| sigs == signatures));
    }
}
