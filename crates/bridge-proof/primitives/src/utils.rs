use bitcoin::{consensus::Encodable, hashes::Hash, Transaction, WitnessCommitment};
use strata_primitives::{buf::Buf32, hash::sha256d};

/// Scans the given coinbase transaction for a witness commitment and returns it if found.
///
/// This function iterates over the outputs of the provided `coinbase` transaction from the end
/// towards the beginning, looking for an output whose `script_pubkey` starts with the "magic" bytes
/// `[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]`. This pattern indicates an `OP_RETURN` with an
/// embedded witness commitment header. If such an output is found, the function extracts the
/// following 32 bytes as the witness commitment and returns a [`WitnessCommitment`].
///
/// Based on: [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/blob/b97be3d4974d40cf348b280718d1367b8148d1ba/bitcoin/src/blockdata/block.rs#L190-L210).
pub fn witness_commitment_from_coinbase(coinbase: &Transaction) -> Option<WitnessCommitment> {
    // Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

    // Commitment is in the last output that starts with magic bytes.
    if let Some(pos) = coinbase
        .output
        .iter()
        .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
    {
        let bytes =
            <[u8; 32]>::try_from(&coinbase.output[pos].script_pubkey.as_bytes()[6..38]).unwrap();
        Some(WitnessCommitment::from_byte_array(bytes))
    } else {
        None
    }
}

/// Computes the [`Txid`](bitcoin::Txid) using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2)
/// for the underlying `sha256d` hash function.
///
/// Equivalent to [`compute_txid`](bitcoin::Transaction::compute_txid)
///
/// This function hashes the transaction **excluding** the segwit data (i.e., the marker, flag
/// bytes, and the witness fields themselves). For non-segwit transactions, which do not have any
/// segwit data, this will be equal to [`compute_wtxid`].
pub fn compute_txid(tx: &Transaction) -> Buf32 {
    let mut vec = Vec::new();

    tx.version.consensus_encode(&mut vec).unwrap();
    tx.input.consensus_encode(&mut vec).unwrap();
    tx.output.consensus_encode(&mut vec).unwrap();
    tx.lock_time.consensus_encode(&mut vec).unwrap();

    sha256d(&vec)
}
