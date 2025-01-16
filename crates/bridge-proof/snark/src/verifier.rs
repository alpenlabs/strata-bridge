use num_bigint::BigUint;
use num_traits::Num;
use strata_sp1_adapter::verify_groth16;
use strata_zkvm::Proof;

pub fn verify_proof(proof: Proof, vkey: String, comitted_values: &[u8]) -> anyhow::Result<()> {
    let vkey_hash = BigUint::from_str_radix(
        vkey.strip_prefix("0x")
            .expect("vkey should start with '0x'"),
        16,
    )
    .expect("Failed to parse vkey hash")
    .to_bytes_be();

    verify_groth16(&proof, &vkey_hash.try_into().unwrap(), comitted_values)?;

    anyhow::Ok(())
}

// #[cfg(test)]
// mod test {
//     use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
//     use strata_proofimpl_bitvm_bridge::BridgeProofPublicParams;

//     use super::*;

//     #[test]
//     fn test_proof_verification() {
//         let proof_data = include_bytes!("../proof_data/proof.bin");
//         let (sp1_proof, sp1_vkey, raw_groth16_proof): (
//             SP1ProofWithPublicValues,
//             SP1VerifyingKey,
//             Proof,
//         ) = bincode::deserialize(proof_data).unwrap();

//         let public_value: BridgeProofPublicParams = sp1_proof.clone().public_values.read();
//         println!("got the public param {:?}", public_value);
//         println!("\n**\n");

//         let obtained_bytes = bincode::serialize(&public_value).unwrap();
//         let expected_bytes = sp1_proof.public_values.as_slice();
//         println!("Committed values {:?}", obtained_bytes);
//         println!("\n**\n");
//         println!("Ex values {:?}", expected_bytes);
//         println!("\n**\n");
//         assert_eq!(obtained_bytes, expected_bytes);

//         let vkey_str = sp1_vkey.bytes32();
//         println!("Raw proof: {:?}", raw_groth16_proof);
//         println!("\n**\n");
//         println!("Vkey bytes32 str: {:?}", vkey_str);

//         let commited_values = sp1_proof.public_values.as_slice();
//         verify_proof(raw_groth16_proof, vkey_str, commited_values).unwrap();
//     }

//     #[test]
//     fn test_serialize_public_inputs() {
//         // let data = &[
//         //     32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0,         // 0,     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         // 0, 0, 0, 0, 0,     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         // 0, 0, 0, 0, 0, ];

//         let public_inputs: BridgeProofPublicParams = (
//             std::array::from_fn(|i| i as u8),
//             std::array::from_fn(|i| 2 * i as u8),
//             std::array::from_fn(|i| 3 * i as u8),
//             0x12345678,
//         );

//         let serialized_public_inputs = bincode::serialize(&public_inputs).unwrap();

//         println!("data: {:?}", serialized_public_inputs);
//         println!("length: {:?}", serialized_public_inputs.len());

//         let public_inputs: BridgeProofPublicParams =
//             bincode::deserialize(&serialized_public_inputs).unwrap();

//         println!("{:?}", public_inputs);
//     }
// }
