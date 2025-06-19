//! This module contains the generators for connectors used in the Assert Chain.
use std::array;

use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};
use bitvm::{
    signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256, HASH_LEN},
    treepp::*,
};
use strata_bridge_primitives::scripts::prelude::*;

/// Factory for crafting connectors with 256-bit WOTS public keys.
///
/// The layout is based on the number of public keys per connector and the total number of public
/// keys. The value of `N_PUBLIC_KEYS_PER_CONNECTOR` must be chosen such that the stack size when
/// spending any of these connectors does not exceed the maximum stack size supported by Bitcoin's
/// consensus rules.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorA256Factory<
    const N_BATCH_1: usize,
    const N_FIELD_ELEMS_BATCH_1: usize,
    const N_BATCH_2: usize,
    const N_FIELD_ELEMS_BATCH_2: usize,
> where
    [(); N_BATCH_1 * N_FIELD_ELEMS_BATCH_1 + N_BATCH_2 * N_FIELD_ELEMS_BATCH_2]:,
{
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 256-bit WOTS public keys used for bitcommitments.
    pub public_keys: [<wots256 as Wots>::PublicKey;
        N_BATCH_1 * N_FIELD_ELEMS_BATCH_1 + N_BATCH_2 * N_FIELD_ELEMS_BATCH_2],
}

impl<
        const N_BATCH_1: usize,
        const N_FIELD_ELEMS_BATCH_1: usize,
        const N_BATCH_2: usize,
        const N_FIELD_ELEMS_BATCH_2: usize,
    > ConnectorA256Factory<N_BATCH_1, N_FIELD_ELEMS_BATCH_1, N_BATCH_2, N_FIELD_ELEMS_BATCH_2>
where
    [(); N_BATCH_1 * N_FIELD_ELEMS_BATCH_1 + N_BATCH_2 * N_FIELD_ELEMS_BATCH_2]:,
{
    /// Constructs connectors from the public keys.
    ///
    /// The public keys are split into two batches each with some number of field elements.
    pub fn create_connectors(
        &self,
    ) -> (
        [ConnectorA256<N_FIELD_ELEMS_BATCH_1>; N_BATCH_1],
        [ConnectorA256<N_FIELD_ELEMS_BATCH_2>; N_BATCH_2],
    ) {
        let connectors1: [ConnectorA256<N_FIELD_ELEMS_BATCH_1>; N_BATCH_1] =
            array::from_fn(|i| ConnectorA256::<N_FIELD_ELEMS_BATCH_1> {
                network: self.network,
                public_keys: self.public_keys
                    [i * N_FIELD_ELEMS_BATCH_1..(i + 1) * N_FIELD_ELEMS_BATCH_1]
                    .try_into()
                    .expect("array size must be N_FIELD_ELEMS_BATCH_1"),
            });

        let connectors2: [ConnectorA256<N_FIELD_ELEMS_BATCH_2>; N_BATCH_2] = array::from_fn(|i| {
            let offset = N_BATCH_1 * N_FIELD_ELEMS_BATCH_1;
            ConnectorA256::<N_FIELD_ELEMS_BATCH_2> {
                network: self.network,
                public_keys: self.public_keys
                    [offset + i * N_FIELD_ELEMS_BATCH_2..offset + (i + 1) * N_FIELD_ELEMS_BATCH_2]
                    .try_into()
                    .expect("array size must be N_FIELD_ELEMS_BATCH_2"),
            }
        });

        (connectors1, connectors2)
    }
}

/// A connector with 256-bit WOTS public keys.
#[derive(Debug, Clone)]
pub struct ConnectorA256<const N_PUBLIC_KEYS: usize> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 256-bit WOTS public keys used for bitcommitments.
    pub public_keys: [<wots256 as Wots>::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA256<N_PUBLIC_KEYS> {
    /// Creates the locking script for the connector.
    ///
    /// This script verifies the WOTS signatures for the public keys and returns `OP_TRUE`.
    pub fn create_locking_script(&self) -> ScriptBuf {
        const MSG_LEN: usize = wots256::MSG_BYTE_LEN as usize;
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots256::checksig_verify(&public_key) }

                for _ in 0..(MSG_LEN * 8)/4 { OP_DROP } // drop the nibbles
            }

            OP_TRUE
        }
        .compile()
    }

    /// Creates the taproot address for this connector composed of all the locking scripts.
    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    /// Creates the spend info for the connector.
    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();

        let (_, spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to create the taproot");

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script must be part of the address");

        (script, control_block)
    }

    /// Finalizes the input for the psbt that spends this connector.
    pub fn finalize_input(
        &self,
        input: &mut Input,
        signatures: [<wots256 as Wots>::Signature; N_PUBLIC_KEYS],
    ) {
        let witness = script! {
            for sig in signatures { { wots256::signature_to_raw_witness(&sig) } }
        };

        let mut witness_stack = taproot_witness_signatures(witness);

        let (script, control_block) = self.generate_spend_info();

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}

/// Factory for crafting connectors with WOTS public keys for hashes.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorAHashFactory<
    const N_BATCH_1: usize,
    const N_HASHES_BATCH_1: usize,
    const N_BATCH_2: usize,
    const N_HASHES_BATCH_2: usize,
> where
    [(); N_BATCH_1 * N_HASHES_BATCH_1 + N_BATCH_2 * N_HASHES_BATCH_2]:,
{
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The WOTS public keys used for bitcommiting hashes.
    pub public_keys: [<wots_hash as Wots>::PublicKey;
        N_BATCH_1 * N_HASHES_BATCH_1 + N_BATCH_2 * N_HASHES_BATCH_2],
}

impl<
        const N_BATCH_1: usize,
        const N_HASHES_BATCH_1: usize,
        const N_BATCH_2: usize,
        const N_HASHES_BATCH_2: usize,
    > ConnectorAHashFactory<N_BATCH_1, N_HASHES_BATCH_1, N_BATCH_2, N_HASHES_BATCH_2>
where
    [(); N_BATCH_1 * N_HASHES_BATCH_1 + N_BATCH_2 * N_HASHES_BATCH_2]:,
{
    /// Constructs connectors from the public keys.
    ///
    /// The public keys are split into chunks of `N_PUBLIC_KEYS_PER_CONNECTOR` and the remaining
    /// ones are put into a separate connector.
    pub fn create_connectors(
        &self,
    ) -> (
        [ConnectorAHash<N_HASHES_BATCH_1>; N_BATCH_1],
        [ConnectorAHash<N_HASHES_BATCH_2>; N_BATCH_2],
    ) {
        let connectors1 = array::from_fn(|i| ConnectorAHash::<N_HASHES_BATCH_1> {
            network: self.network,
            public_keys: self.public_keys[i * N_HASHES_BATCH_1..(i + 1) * N_HASHES_BATCH_1]
                .try_into()
                .expect("array size must be N_HASHES_BATCH_1"),
        });

        let connectors2 = array::from_fn(|i| {
            let offset = N_BATCH_1 * N_HASHES_BATCH_1;
            ConnectorAHash::<N_HASHES_BATCH_2> {
                network: self.network,
                public_keys: self.public_keys
                    [offset + i * N_HASHES_BATCH_2..offset + (i + 1) * N_HASHES_BATCH_2]
                    .try_into()
                    .expect("array size must be N_HASHES_BATCH_2"),
            }
        });

        (connectors1, connectors2)
    }
}

/// Connector with WOTS public keys for hashes.
#[derive(Debug, Clone)]
pub struct ConnectorAHash<const N_PUBLIC_KEYS: usize> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 160-bit WOTS public keys used for bitcommitments.
    pub public_keys: [<wots_hash as Wots>::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorAHash<N_PUBLIC_KEYS> {
    /// Creates the locking script for the connector.
    ///
    /// This script verifies the WOTS signatures for the public keys and returns `OP_TRUE`.
    pub fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots_hash::checksig_verify(&public_key) }

                for _ in 0..(HASH_LEN * 8)/4 { OP_DROP } // drop the nibbles
            }
            OP_TRUE
        }
        .compile()
    }

    /// Creates the taproot address for this connector composed of all the locking scripts.
    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    /// Creates the taproot spend info for this connector.
    pub fn create_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();

        let (_, spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to add script");

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script must be part of the address");

        (script, control_block)
    }

    /// Finalizes the input for the psbt that spends this connector.
    pub fn finalize_input(
        &self,
        input: &mut Input,
        signatures: [<wots_hash as Wots>::Signature; N_PUBLIC_KEYS],
    ) {
        let witness = script! {
            for sig in signatures { { wots_hash::signature_to_raw_witness(&sig) } }
        };

        let mut witness_stack = taproot_witness_signatures(witness);

        let (script, control_block) = self.create_spend_info();

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}
