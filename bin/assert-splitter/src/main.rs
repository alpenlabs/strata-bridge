use assert_splitter::{average_size, field_elements_witness_size, hash_witness_size, LayoutData};
use bitvm::chunk::config::{NUM_U160, NUM_U256};

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

    let field_elements_layout = LayoutData::from(avg_field_element, NUM_U256 + 2);
    println!(
        "\nField Elements Layout: \n----------------------------------\n{}\n",
        field_elements_layout
    );

    let tx_size = average_size(
        count,
        num_inputs,
        field_elements_layout.max_elements_per_utxo,
        field_elements_witness_size,
    );
    println!("{}", tx_size);

    let hash_layout = LayoutData::from(avg_hash, NUM_U160);
    println!(
        "\nHash Layout: \n----------------------------------\n{}\n",
        hash_layout
    );

    let tx_size = average_size(
        count,
        num_inputs,
        hash_layout.max_elements_per_utxo,
        hash_witness_size,
    );
    println!("{}", tx_size);
}
