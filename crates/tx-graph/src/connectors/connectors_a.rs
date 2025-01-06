#![allow(unused)]
use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf,
};
use bitvm::{
    bigint::U254,
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    signatures::{
        self,
        wots::{wots160, wots256, SignatureImpl},
    },
    treepp::*,
};
use strata_bridge_primitives::scripts::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct ConnectorA256Factory<
    const N_PUBLIC_KEYS_PER_CONNECTOR: usize,
    const N_PUBLIC_KEYS: usize,
> {
    pub network: Network,

    pub public_keys: [wots256::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS_PER_CONNECTOR: usize, const N_PUBLIC_KEYS: usize>
    ConnectorA256Factory<N_PUBLIC_KEYS_PER_CONNECTOR, N_PUBLIC_KEYS>
{
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

#[derive(Debug, Clone)]
pub struct ConnectorA256<const N_PUBLIC_KEYS: usize> {
    pub network: Network,
    pub public_keys: [wots256::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA256<N_PUBLIC_KEYS> {
    pub fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots256::checksig_verify(public_key, true) }
                // { wots256::checksig_verify(public_key, false) }
                // for _ in 0..32 { { 62 } OP_ROLL { 63 } OP_ROLL }
                // { fq_from_nibbles() }
                // { U254::push_hex(Fq::MODULUS) }
                // { U254::greaterthan(0, 1) } OP_VERIFY
            }

            OP_TRUE
        }
        .compile()
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

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

    pub fn create_tx_input(
        &self,
        input: &mut Input,
        msk: &str,
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

#[derive(Debug, Clone, Copy)]
pub struct ConnectorA160Factory<
    const N_PUBLIC_KEYS_PER_CONNECTOR: usize,
    const N_PUBLIC_KEYS: usize,
> {
    pub network: Network,

    pub public_keys: [wots160::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS_PER_CONNECTOR: usize, const N_PUBLIC_KEYS: usize>
    ConnectorA160Factory<N_PUBLIC_KEYS_PER_CONNECTOR, N_PUBLIC_KEYS>
{
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

#[derive(Debug, Clone)]
pub struct ConnectorA160<const N_PUBLIC_KEYS: usize> {
    pub network: Network,
    pub public_keys: [wots160::PublicKey; N_PUBLIC_KEYS],
}

impl<const N_PUBLIC_KEYS: usize> ConnectorA160<N_PUBLIC_KEYS> {
    pub fn create_locking_script(&self) -> ScriptBuf {
        script! {
            for &public_key in self.public_keys.iter().rev() {
                { wots160::checksig_verify(public_key, true) }
            }
            // for _ in 0..self.public_keys.len() {
            //     for _ in 0..self.public_keys[0].len() {
            //         OP_2DROP
            //     }
            // }
            OP_TRUE
        }
        .compile()
    }

    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

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

    pub fn create_tx_input(
        &self,
        input: &mut Input,
        msk: &str,
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
