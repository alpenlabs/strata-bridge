use bitvm::{
    chunk::api::Signatures as g16Signatures,
    signatures::wots_api::{wots256, wots_hash},
    treepp::*,
};

use crate::{
    constants::*,
    errors::{ParseError, ParseResult},
};

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

pub fn parse_assertion_witnesses(
    witness256_batch1: [Script; NUM_FIELD_CONNECTORS_BATCH_1],
    witness256_batch2: [Script; NUM_FIELD_CONNECTORS_BATCH_2],
    witness160_batch1: [Script; NUM_HASH_CONNECTORS_BATCH_1],
    witness160_batch2: [Script; NUM_HASH_CONNECTORS_BATCH_2],
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

    let mut w160 = Vec::with_capacity(NUM_HASH_CONNECTORS_BATCH_1);
    for witness in witness160_batch1.into_iter() {
        w160.push(parse_wots_hash_signatures::<
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
        >(witness)?);
    }

    let mut w160 = w160.into_iter().flatten().collect::<Vec<_>>();

    for witness in witness160_batch2.into_iter() {
        w160.extend(parse_wots_hash_signatures::<
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
        >(witness)?);
    }

    Ok((
        Box::new([w256[0]]), // proof public input
        Box::new(w256[1..].try_into().unwrap()),
        Box::new(w160.try_into().unwrap()),
    ))
}

#[cfg(test)]
mod tests {
    use bitvm::{
        signatures::wots_api::{wots256, wots_hash, SignatureImpl},
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

        let signatures: [_; N_SIGS] =
            std::array::from_fn(|i| wots256::get_signature(&secrets[i], &create_message::<32>(i)));

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots256::get_signature(&secrets[i], &create_message::<32>(i)).to_script() }
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
            wots_hash::get_signature(&secrets[i], &create_message::<20>(i))
        });

        let signatures_script = script! {
            for i in 0..N_SIGS {
                { wots_hash::get_signature(&secrets[i], &create_message::<20>(i)).to_script() }
            }
        };
        let parsed_signatures = parse_wots_hash_signatures::<N_SIGS>(signatures_script);

        assert!(parsed_signatures.is_ok_and(|sigs| sigs == signatures));
    }
}
