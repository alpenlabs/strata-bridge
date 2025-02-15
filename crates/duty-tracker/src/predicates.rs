fn op_return_data(script: &Script) -> Option<&[u8]> {
    let mut instructions = script.instructions();
    if let Some(Ok(bitcoin::script::Instruction::Op(OP_RETURN))) = instructions.next() {
        // NOOP
    } else {
        return None;
    }

    if let Some(Ok(bitcoin::script::Instruction::PushBytes(bytes))) = instructions.next() {
        Some(bytes.as_bytes())
    } else {
        None
    }
}

fn magic_tagged_data(script: &Script) -> Option<&[u8]> {
    const MAGIC_BYTES: &[u8; 6] = b"strata";
    op_return_data(script).and_then(|data| {
        if data.starts_with(MAGIC_BYTES) {
            Some(&data[MAGIC_BYTES.len()..])
        } else {
            None
        }
    })
}

const EL_ADDR_SIZE: usize = 20;

fn is_deposit_request(tx: &Transaction) -> bool {
    const MERKLE_PROOF_SIZE: usize = 32;
    tx.output.iter().any(|output| {
        if let Some(meta) = magic_tagged_data(&output.script_pubkey) {
            meta.len() == MERKLE_PROOF_SIZE + EL_ADDR_SIZE
        } else {
            false
        }
    })
}

fn is_strata_checkpoint_transaction(tx: &Transaction) -> bool {
    todo!()
}
