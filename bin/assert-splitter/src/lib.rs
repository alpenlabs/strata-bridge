#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

mod chunker_primitives;

use std::fmt::Display;

use ark_ff::UniformRand;
use bitcoin::{hex::DisplayHex, taproot::TAPROOT_CONTROL_BASE_SIZE, VarInt, Weight};
use bitvm::{
    execute_script_without_stack_limit,
    signatures::wots_api::{wots160, wots256},
    treepp::*,
};
use chunker_primitives::*;
use secp256k1::rand::{rngs::OsRng, Rng};

const MAX_STACK_ELEMS: usize = 1000;
const MAX_TX_V3_SIZE: Weight = Weight::from_wu(40000);

/// Layout of assertion data (field elements and hashes) across UTXOs and transactions.
#[derive(Debug, Clone, Copy)]
pub struct LayoutData {
    /// Maximum number of elements that can be committed to a single UTXO.
    pub max_elements_per_utxo: usize,
    /// Maximum number of UTXOs that can be spent in a single transaction.
    pub max_utxos_per_tx: usize,
    /// Number of transactions required to commit all elements with the elements laid out evenly.
    pub num_txs: usize,
    /// Number of elements that remain to be committed after the last transaction (if any).
    pub remainder: Option<usize>,
}

impl Display for LayoutData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Max Elements per UTXO: {}\nMax UTXOs per TX: {}\nNum TXs: {}\nRemainder: {:?}",
            self.max_elements_per_utxo, self.max_utxos_per_tx, self.num_txs, self.remainder
        )
    }
}

impl LayoutData {
    /// Computes the layout of the elements across UTXOs and transactions.
    ///
    /// # Parameters
    ///
    /// * `size_data` - Stack and transaction size information for a single element.
    /// * `num_elements` - Number of elements to commit.
    pub fn from(size_data: SizeData, num_elements: usize) -> Self {
        let max_elements_per_utxo = MAX_STACK_ELEMS / size_data.max_stack_size;
        if max_elements_per_utxo == 0 {
            panic!("No solution exists");
        }

        let mut elements_per_utxo = max_elements_per_utxo;

        while elements_per_utxo != 0 {
            let max_utxos_per_tx = MAX_TX_V3_SIZE
                .checked_div(
                    size_data
                        .tx_size_per_utxo
                        .checked_mul(elements_per_utxo as u64)
                        .expect("must be able to multiply weight")
                        .into(),
                )
                .expect("must be able to divide weight")
                .to_wu() as usize;

            if max_utxos_per_tx > 0 {
                let remainder = num_elements % (elements_per_utxo * max_utxos_per_tx);
                let remainder = if remainder == 0 {
                    None
                } else {
                    Some(remainder)
                };

                return Self {
                    max_elements_per_utxo: elements_per_utxo,
                    max_utxos_per_tx,
                    num_txs: num_elements / (elements_per_utxo * max_utxos_per_tx),
                    remainder,
                };
            }

            // if we cannot fit even a single UTXO in a transaction, we need to split the elements
            // across multiple UTXOs and spend each one in a separate transaction.
            elements_per_utxo -= 1;
        }

        panic!("No solution exists");
    }
}

/// Size data for a single element.
#[derive(Debug, Clone)]
pub struct SizeData {
    /// Max stack used to commit a single element.
    pub max_stack_size: usize,

    /// Size of a transaction with a single UTXO with a single element.
    pub tx_size_per_utxo: Weight,
}

impl Display for SizeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Max Stack Size: {}\nTransaction Size per UTXO: {}",
            self.max_stack_size, self.tx_size_per_utxo
        )
    }
}

/// Computes the average stack and transaction size for a given number of inputs and elements to
/// commit.
///
/// # Parameters
///
/// * `count` - Number of samples to take.
/// * `num_inputs` - Number of inputs in the transaction.
/// * `num_elements` - Number of elements to commit.
/// * `f` - Function that computes the stack and transaction size for some number of inputs each of
///   which commits to some number of elements.
pub fn average_size(
    count: usize,
    num_inputs: usize,
    num_elements: usize,
    f: impl Fn(usize, usize) -> SizeData,
) -> SizeData {
    let mut avg_tx_size: Weight = Weight::from_wu(0);
    let mut avg_max_stack_size = 0;

    for _ in 0..count {
        let info = f(num_inputs, num_elements);
        avg_tx_size = avg_tx_size
            .checked_add(info.tx_size_per_utxo)
            .expect("must be able to sum up tx weights");
        avg_max_stack_size += info.max_stack_size;
    }

    SizeData {
        max_stack_size: avg_max_stack_size / count,
        tx_size_per_utxo: avg_tx_size
            .checked_div(count as u64)
            .expect("must be able to compute average weight"),
    }
}

/// Computes the maximum stack usage and transaction [`Weight`] for a given number of
/// inputs and field elements to commit.
pub fn field_elements_witness_size(num_inputs: usize, num_elements: usize) -> SizeData {
    let secret: [u8; 32] = OsRng.gen();
    let secret = secret.to_lower_hex_string();

    let pubkey = wots256::generate_public_key(&secret);
    let fq = ark_bn254::Fq::rand(&mut OsRng);
    let fq_nibs = extern_fq_to_nibbles(fq);
    let fq_bytes = nib_to_byte_array(&fq_nibs);
    assert_eq!(fq_bytes.len(), 32);

    let fq_sig = wots256::get_signature(&secret, &fq_bytes);
    let fq_lock_script = script! {
        { wots256::checksig_verify(pubkey) }

        for _ in 0..256/4 { OP_DROP } // drop the nibbles
    };

    let witness_script = script! {
        for (sig, digit) in fq_sig {
            { sig.to_vec() }
            { digit }
        }
    };

    let full_script = script! {
        { witness_script.clone() }
        { fq_lock_script.clone() }
    };

    let res = execute_script_without_stack_limit(full_script);
    let max_stack_size = res.stats.max_nb_stack_items;

    let witness_elements = execute_script(witness_script.clone());
    let mut witness_elements = (0..witness_elements.final_stack.len())
        .map(|i| witness_elements.final_stack.get(i))
        .collect::<Vec<_>>();
    witness_elements.push(fq_lock_script.compile().to_bytes());

    let witness_elements = vec![witness_elements; num_elements]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let tx_size = get_total_size(&witness_elements, num_inputs, 2);

    SizeData {
        max_stack_size: max_stack_size * num_elements,
        tx_size_per_utxo: tx_size,
    }
}

/// Computes the maximum stack usage and transaction [`Weight`] for a given number of
/// inputs and hash elements to commit.
pub fn hash_witness_size(num_inputs: usize, num_elements: usize) -> SizeData {
    let secret: [u8; 32] = OsRng.gen();
    let secret = secret.to_lower_hex_string();

    let pubkey = wots160::generate_public_key(&secret);
    let fq = ark_bn254::Fq::rand(&mut OsRng);
    let fq_nibs = extern_hash_fps(vec![fq, fq], true);
    let fq_bytes: [u8; 32] = nib_to_byte_array(&fq_nibs).try_into().unwrap();
    assert_eq!(fq_bytes.len(), 32);

    let fq_bytes: [u8; 20] = fq_bytes[12..32].try_into().unwrap();
    let fq_sig = wots160::get_signature(&secret, &fq_bytes);
    let fq_lock_script = script! {
        { wots160::checksig_verify(pubkey) }

        for _ in 0..160/4 { OP_DROP } // drop the nibbles
    };

    let witness_script = script! {
        for (sig, digit) in fq_sig {
            { sig.to_vec() }
            { digit }
        }
    };

    let full_script = script! {
        { witness_script.clone() }
        { fq_lock_script.clone() }
    };

    let res = execute_script_without_stack_limit(full_script);
    let max_stack_size = res.stats.max_nb_stack_items;

    let witness_elements = execute_script(witness_script.clone());
    let mut witness_elements = (0..witness_elements.final_stack.len())
        .map(|i| witness_elements.final_stack.get(i))
        .collect::<Vec<_>>();
    witness_elements.push(fq_lock_script.compile().to_bytes());

    let witness_elements = vec![witness_elements; num_elements]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let tx_size = get_total_size(&witness_elements, num_inputs, 2);

    SizeData {
        max_stack_size: max_stack_size * num_elements,
        tx_size_per_utxo: tx_size,
    }
}

/// Gets the total size of a segwit transaction with the given number of inputs and outputs and
/// witnesses.
///
/// The witnesses include the signatures and the script. It is assumed that the taproot output only
/// contains a single script.
//
// FIXME: It is assumed that the same witness is added to each input as this
// script is only concerned with the size of the data and not its validity. Generalize this to
// accept multiple witness lengths.
pub fn get_total_size(witnesses: &[Vec<u8>], num_inputs: usize, num_outputs: usize) -> Weight {
    const VERSION: usize = 4;

    const INPUT_COUNT: usize = 1;
    const INPUT_TXID: usize = 32;
    const INPUT_VOUT: usize = 4;
    const INPUT_SCRIPT_LENGTH: usize = 1;
    const INPUT_SEQUENCE: usize = 4;

    const OUTPUT_COUNT: usize = 1;
    const OUTPUT_VALUE: usize = 8;
    const OUTPUT_SCRIPT_LENGTH: usize = 1;
    const OUTPUT_SCRIPTPUBKEY_LENGTH: usize = 34;

    const LOCKTIME: usize = 4;

    let base_size: usize = VERSION
        + INPUT_COUNT
        + num_inputs * (INPUT_TXID + INPUT_VOUT + INPUT_SCRIPT_LENGTH + INPUT_SEQUENCE)
        + OUTPUT_COUNT
        + num_outputs * (OUTPUT_VALUE + OUTPUT_SCRIPT_LENGTH + OUTPUT_SCRIPTPUBKEY_LENGTH)
        + LOCKTIME;

    const SEGWIT_MULTIPLIER: usize = 4;
    const SEGWIT_MARKER: usize = 1;
    const SEGWIT_FLAG: usize = 1;

    const CONTROL_BLOCK_BASE_SIZE: usize = TAPROOT_CONTROL_BASE_SIZE; // for single script, there is no branch.
    const CONTROL_BLOCK_LENGTH: usize = VarInt(CONTROL_BLOCK_BASE_SIZE as u64).size();

    let num_witness_elements: usize = VarInt::from((witnesses.len() + 1) as u64).size(); // +1 for the control block
    let witness_contributions = witnesses
        .iter()
        .map(|w| w.len() + VarInt::from(w.len() as u64).size())
        .sum::<usize>();

    let weight = SEGWIT_MULTIPLIER * base_size
        + SEGWIT_MARKER
        + SEGWIT_FLAG
        + num_inputs
            * (num_witness_elements
                + witness_contributions
                + CONTROL_BLOCK_LENGTH
                + CONTROL_BLOCK_BASE_SIZE);

    Weight::from_wu(weight as u64)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, sighash::SighashCache, taproot::LeafVersion, transaction, Amount, Network,
        OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitvm::treepp::*;
    use proptest::prelude::*;
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_primitives::scripts::taproot::{create_taproot_addr, SpendPath};
    use strata_bridge_test_utils::prelude::{generate_keypair, generate_txid};

    use super::*;

    proptest! {

        #[test]
        fn test_total_size(num_inputs in 1..10usize, num_outputs in 1..10usize, witness in prop::collection::vec(any::<Vec<u8>>(), 2..10usize)) {
            let keypair = generate_keypair();
            let xonly_pubkey = keypair.x_only_public_key().0;

            let locking_script = script! {
                { xonly_pubkey }
                OP_CHECKSIG
            }
            .compile();

            let (_address, spend_info) = create_taproot_addr(
                &Network::Regtest,
                SpendPath::ScriptSpend {
                    scripts: &[locking_script.clone()],
                },
            )
            .expect("must be able to construct taproot address");

            let control_block = spend_info
                .control_block(&(locking_script.clone(), LeafVersion::TapScript))
                .expect("must be able to get control block");

            const TOTAL_AMOUNT: Amount = Amount::from_sat(1_000_000);

            const FEES: Amount = Amount::from_sat(1000);

            let inputs = vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: generate_txid(),
                        vout: OsRng.gen(),
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                };
                num_inputs
            ];

            let outputs = vec![
                TxOut {
                    value: TOTAL_AMOUNT / 2 - FEES,
                    script_pubkey: locking_script.clone(),
                };
                num_outputs
            ];

            let mut tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: inputs.to_vec(),
                output: outputs.to_vec(),
            };

            let mut sighasher = SighashCache::new(&mut tx);
            (0..num_inputs).for_each(|i| {
                witness.iter().for_each(|w| {
                    sighasher
                        .witness_mut(i)
                        .expect("must have witness")
                        .push(w.clone());
                });

                let control_block_bytes = control_block.serialize();
                sighasher
                    .witness_mut(i)
                    .expect("must have witness")
                    .push(control_block_bytes.clone());

            });

            let signed_tx = sighasher.into_transaction();

            let expected_size = signed_tx.weight();

            let actual_size = get_total_size(&witness, num_inputs, num_outputs);

            assert_eq!(actual_size, expected_size, "total size must match");
        }
    }
}
