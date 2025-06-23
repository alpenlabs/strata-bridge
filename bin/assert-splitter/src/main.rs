//! Binary to print the average size of the assertion data across UTXOs and transactions.

// Dependencies used by the library but not directly by the binary
use ark_bn254 as _;
use ark_ff as _;
use assert_splitter::{average_size, field_elements_witness_size, hash_witness_size, LayoutData};
use bitcoin as _;
use bitcoin_script as _;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use blake3 as _;
#[cfg(test)]
use proptest as _;
use secp256k1 as _;
use strata_bridge_primitives as _;
#[cfg(test)]
use strata_bridge_primitives as _;
#[cfg(test)]
use strata_bridge_test_utils as _;

fn main() {
    let count = 100;
    let num_inputs = 1;
    let avg_field_element = average_size(count, num_inputs, 1, field_elements_witness_size);
    let avg_hash = average_size(count, num_inputs, 1, hash_witness_size);

    println!(
        "Average Field Element Max Stack Size: {}",
        avg_field_element.max_stack_size
    );
    println!(
        "Average Field Element Transaction Size: {}",
        avg_field_element.tx_size_per_utxo
    );

    println!("Average Hash Max stack size: {}", avg_hash.max_stack_size);
    println!(
        "Average Hash Transaction size: {}",
        avg_hash.tx_size_per_utxo
    );

    let field_elements_layout = LayoutData::from(avg_field_element, NUM_U256 + NUM_PUBS);
    println!(
        "\nField Elements Layout: \n----------------------------------\n{field_elements_layout}\n"
    );

    let tx_size = average_size(
        count,
        num_inputs,
        field_elements_layout.max_elements_per_utxo,
        field_elements_witness_size,
    );
    println!("{tx_size}");

    let hash_layout = LayoutData::from(avg_hash, NUM_HASH);
    println!("\nHash Layout: \n----------------------------------\n{hash_layout}\n");

    let tx_size = average_size(
        count,
        num_inputs,
        hash_layout.max_elements_per_utxo,
        hash_witness_size,
    );
    println!("{tx_size}");
}
