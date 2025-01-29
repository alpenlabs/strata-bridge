use bitcoin::{
    key::Parity,
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_EQUALVERIFY, OP_SHA256, OP_SIZE},
    psbt::Input,
    relative, Address, Network, ScriptBuf,
};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};
use strata_bridge_primitives::{params::tx::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*};

/// The connector to move the operator's stake across transactions.
// TODO: Replace this with `ConnectorStake`.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorS {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorS {
    /// Creates a new `ConnectorS` with the given N-of-N aggregated public key and the
    /// bitcoin network.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Creates a taproot address with key spend path for the given operator set.
    pub fn create_taproot_address(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("must be able to create taproot address");

        addr
    }

    /// Finalizes a psbt input where this connector is used with the provided signature.
    ///
    /// # Note
    ///
    /// This method does not check if the signature is valid for the input. It is the caller's
    /// responsibility to ensure that the signature is valid.
    ///
    /// If the psbt input is already in the final state, then this method overrides the signature.
    pub fn create_tx_input(&self, signature: Signature, input: &mut Input) {
        finalize_input(input, [signature.as_ref()]);
    }
}

/// The connector to move the operator's stake across Stake transactions.
///
/// It is used in the Disprove and Slash Stake `k` transactions, where `k` is the index of the
/// stake transaction.
///
/// The operator can also advance the stake chain by revealing the pre-image, along with a valid
/// signature from the operator's public key.
/// Note that the stake advancement is done by the `stake-chain` crate.
///
/// To illustrate the concept, let's say that an operator wants to claim the `k`th bridged-in UTXO.
/// For this, they need the `k`th Claim Transaction and hence the `k`th stake transaction. An
/// operator is not required to periodically advance the stake chain, so it may be the case that
/// they have only posted the `k-n`th stake chain. In this case, they post the next `n` stake
/// transactions at an interval of `ΔS`. We can set the value of `ΔS` to a small enough value while
/// still preventing an operator from spamming the system with faulty claims. Once the chain has
/// been advanced, they can use the `k`th stake to make their claim.
///
/// If the operator tries to advance the chain to the `k+1`th stake, they are required to reveal a
/// pre-image (publicly) on bitcoin. Using this stake, anybody can post the Burn Payouts transaction
/// which renders it impossible for an operator to receive a payout (optimistically or otherwise).
///
/// If the operator has received a `k`th Payout Optimistic or Payout transaction, they can advance
/// the stake chain (revealing the pre-image) without fear. It is the responsibility of the
/// [`ConnectorP`](super::connector_p::ConnectorP) and [`ConnectorStake`] to ensure that will make
/// it impossible make it impossible
///
/// # Security
///
/// An operator can only advance the stake chain if they reveal the pre-image along with a valid
/// signature from the operator's public key. Hence, the operator must must be able to provide the
/// pre-image to the [`ConnectorStake`]. It is advised to use a secure storage mechanism to store
/// the pre-image, and optionally a deterministic key derivation function to derive the pre-image
/// from something such as an operator's master entropy.
// TODO: This should replace the `ConnectorS` struct above.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorStake {
    /// The N-of-N aggregated public key for the operator set.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The operator's public key.
    operator_pubkey: XOnlyPublicKey,

    /// The corresponding pre-image for the `k`th stake.
    ///
    /// This is a 32-byte array, that should be generated securely from the operator's master
    /// entropy along with the `k`th stake's index.
    ///
    /// A suggestion is to hash them together, i.e. SHA256(master entropy || stake_index), and take
    /// the 32 bytes of the resulting hash.
    stake_preimage: [u8; 32],

    /// The `ΔS` interval relative timelock to advance the stake chain.
    delta: relative::LockTime,

    /// The bitcoin network on which the connector operates.
    network: Network,
}

impl ConnectorStake {
    /// Creates a new [`ConnectorStake`] with the given N-of-N aggregated public key, `k`th stake
    /// preimage, and the bitcoin network.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        stake_preimage: [u8; 32],
        delta: relative::LockTime,
        network: Network,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_preimage,
            delta,
            network,
        }
    }

    /// Creates a P2TR address with key spend path for the given operator set and no script paths.
    ///
    /// This is used both in the Disprove and in the Slash Stake `k` transactions.
    pub fn create_n_of_n(&self) -> Address {
        let (addr, _spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::KeySpend {
                internal_key: self.n_of_n_agg_pubkey,
            },
        )
        .expect("must be able to create taproot address");

        addr
    }

    /// Creates a P2TR address with an unspendable key spend path and a single script path that can
    /// be unlocked by revealing the pre-image, and assuring that the `ΔS` relative timelock
    /// interval has passed.
    ///
    /// This is used to advance the stake chain.
    ///
    /// Due to security reasons, the locking script is also secured by a valid signature from
    /// the operator's public key.
    ///
    /// # Implementation Details
    ///
    /// The locking script can be represented as the following miniscript policy:
    ///
    /// ```text
    /// thresh(3,pk(operator_pubkey), sha256(stake_preimage), older(ΔS))
    /// ```
    ///
    /// which compiles to the following script:
    ///
    /// ```text
    /// <operator_pubkey> OP_CHECKSIGVERIFY OP_SIZE <20> OP_EQUALVERIFY OP_SHA256
    /// <stake_preimage> OP_EQUALVERIFY <ΔS> OP_CHECKSEQUENCEVERIFY
    /// ```
    pub fn create_pre_image_timelock(&self) -> ScriptBuf {
        let script = ScriptBuf::builder()
            .push_key(&self.operator_pubkey.public_key(Parity::Even).into())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_SIZE)
            .push_int(20)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(self.stake_preimage)
            .push_opcode(OP_EQUALVERIFY)
            .push_sequence(self.delta.into())
            .push_opcode(OP_CSV)
            .into_script();
        let (taproot_address, _) = create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: *UNSPENDABLE_INTERNAL_KEY,
                scripts: &[script],
            },
        )
        .expect("should be able to create taproot address");

        taproot_address.script_pubkey()
    }

    /// Finalizes a psbt input where this connector is used with the provided signature.
    ///
    /// # Note
    ///
    /// This method does not check if the signature is valid for the input. It is the caller's
    /// responsibility to ensure that the signature is valid.
    ///
    /// If the psbt input is already in the final state, then this method overrides the signature.
    pub fn create_tx_input(&self, signature: Signature, input: &mut Input) {
        finalize_input(input, [signature.as_ref()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pre_image_timelock() {
        todo!()
    }
}
