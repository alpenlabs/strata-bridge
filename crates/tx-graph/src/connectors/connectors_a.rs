use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};
use bitvm::{
    signatures::wots::{wots160, wots256, SignatureImpl},
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
    const N_PUBLIC_KEYS_PER_CONNECTOR: usize,
    const N_PUBLIC_KEYS: usize,
> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 256-bit WOTS public keys used for bitcommitments.
    pub public_keys: [wots256::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS_PER_CONNECTOR: usize, const N_PUBLIC_KEYS: usize>
    ConnectorA256Factory<N_PUBLIC_KEYS_PER_CONNECTOR, N_PUBLIC_KEYS>
{
    /// Constructs connectors from the public keys.
    ///
    /// The public keys are split into chunks of `N_PUBLIC_KEYS_PER_CONNECTOR` and the remaining
    /// ones are put into a separate connector.
    pub fn create_connectors(
        &self,
    ) -> (
        Vec<ConnectorA256<N_PUBLIC_KEYS_PER_CONNECTOR>>,
        ConnectorA256<{ N_PUBLIC_KEYS % N_PUBLIC_KEYS_PER_CONNECTOR }>,
    ) {
        let mut connectors: Vec<ConnectorA256<N_PUBLIC_KEYS_PER_CONNECTOR>> =
            Vec::with_capacity(N_PUBLIC_KEYS / N_PUBLIC_KEYS_PER_CONNECTOR);

        let mut chunks = self.public_keys.chunks_exact(N_PUBLIC_KEYS_PER_CONNECTOR);
        for chunk in chunks.by_ref() {
            let connector = ConnectorA256::<N_PUBLIC_KEYS_PER_CONNECTOR> {
                network: self.network,
                public_keys:
                    TryInto::<[wots256::PublicKey; N_PUBLIC_KEYS_PER_CONNECTOR]>::try_into(chunk)
                        .unwrap(),
            };

            connectors.push(connector);
        }

        let remaining = chunks.remainder();
        let connector = ConnectorA256::<{ N_PUBLIC_KEYS % N_PUBLIC_KEYS_PER_CONNECTOR }> {
            network: self.network,
            public_keys: remaining.try_into().unwrap(),
        };

        (connectors, connector)
    }
}

/// A connector with 256-bit WOTS public keys.
#[derive(Debug, Clone)]
pub struct ConnectorA256<const N_PUBLIC_KEYS: usize> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 256-bit WOTS public keys used for bitcommitments.
    pub public_keys: [wots256::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA256<N_PUBLIC_KEYS> {
    /// Creates the locking script for the connector.
    ///
    /// This script verifies the WOTS signatures for the public keys and returns `OP_TRUE`.
    pub fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots256::checksig_verify(public_key, true) }
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
    pub fn create_tx_input(
        &self,
        input: &mut Input,
        signatures: [wots256::Signature; N_PUBLIC_KEYS],
    ) {
        let witness = script! {
            for sig in signatures { { sig.to_script() } }
        };

        let mut witness_stack = taproot_witness_signatures(witness);

        let (script, control_block) = self.generate_spend_info();

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}

/// Factory for crafting connectors with 160-bit WOTS public keys.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorA160Factory<
    const N_PUBLIC_KEYS_PER_CONNECTOR: usize,
    const N_PUBLIC_KEYS: usize,
> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 160-bit WOTS public keys used for bitcommitments.
    pub public_keys: [wots160::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS_PER_CONNECTOR: usize, const N_PUBLIC_KEYS: usize>
    ConnectorA160Factory<N_PUBLIC_KEYS_PER_CONNECTOR, N_PUBLIC_KEYS>
{
    /// Constructs connectors from the public keys.
    ///
    /// The public keys are split into chunks of `N_PUBLIC_KEYS_PER_CONNECTOR` and the remaining
    /// ones are put into a separate connector.
    pub fn create_connectors(
        &self,
    ) -> (
        Vec<ConnectorA160<N_PUBLIC_KEYS_PER_CONNECTOR>>,
        ConnectorA160<{ N_PUBLIC_KEYS % N_PUBLIC_KEYS_PER_CONNECTOR }>,
    ) {
        let mut connectors: Vec<ConnectorA160<N_PUBLIC_KEYS_PER_CONNECTOR>> = vec![];

        let mut chunks = self.public_keys.chunks_exact(N_PUBLIC_KEYS_PER_CONNECTOR);
        for chunk in chunks.by_ref() {
            let connector = ConnectorA160::<N_PUBLIC_KEYS_PER_CONNECTOR> {
                network: self.network,
                public_keys:
                    TryInto::<[wots160::PublicKey; N_PUBLIC_KEYS_PER_CONNECTOR]>::try_into(chunk)
                        .unwrap(),
            };

            connectors.push(connector);
        }

        let remaining = chunks.remainder();
        let connector = ConnectorA160 {
            network: self.network,
            public_keys: remaining.try_into().unwrap(),
        };

        (connectors, connector)
    }
}

/// Connector with 160-bit WOTS public keys.
#[derive(Debug, Clone)]
pub struct ConnectorA160<const N_PUBLIC_KEYS: usize> {
    /// The bitcoin network for which to generate output addresses.
    pub network: Network,

    /// The 160-bit WOTS public keys used for bitcommitments.
    pub public_keys: [wots160::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA160<N_PUBLIC_KEYS> {
    /// Creates the locking script for the connector.
    ///
    /// This script verifies the WOTS signatures for the public keys and returns `OP_TRUE`.
    pub fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots160::checksig_verify(public_key, true) }
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
    pub fn create_tx_input(
        &self,
        input: &mut Input,
        signatures: [wots160::Signature; N_PUBLIC_KEYS],
    ) {
        let witness = script! {
            for sig in signatures { { sig.to_script() } }
        };

        let mut witness_stack = taproot_witness_signatures(witness);

        let (script, control_block) = self.create_spend_info();

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}
