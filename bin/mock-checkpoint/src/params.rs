use std::sync::Arc;

use secp256k1::{Secp256k1, SecretKey};
use strata_bridge_common::tracing::info;
use strata_btcio::writer::builder::EnvelopeConfig;
use strata_primitives::{
    block_credential::CredRule,
    buf::Buf32,
    operator::OperatorPubkeys,
    params::{OperatorConfig, Params, ProofPublishMode, RollupParams, SyncParams},
    proof::RollupVerifyingKey,
};

use crate::Args;

pub(crate) fn create_envelope_config(args: &Args) -> EnvelopeConfig {
    let pubkey = derive_schnorr_pubkey(&args.sequencer_xpriv);
    // just use the same key for simplicity
    let op_pubkey = OperatorPubkeys::new(pubkey, pubkey);
    let rollup_params = Params {
        rollup: RollupParams {
            rollup_name: args.rollup_name.clone(),
            block_time: 100,
            da_tag: args.da_tag.clone(),
            checkpoint_tag: args.checkpoint_tag.clone(),
            cred_rule: CredRule::SchnorrKey(pubkey),
            horizon_l1_height: 100,
            genesis_l1_height: 100,
            operator_config: OperatorConfig::Static(vec![op_pubkey]),
            evm_genesis_block_hash: Buf32::zero(),
            evm_genesis_block_state_root: Buf32::zero(),
            l1_reorg_safe_depth: 4,
            target_l2_batch_size: 4,
            address_length: 20,
            deposit_amount: 10,
            rollup_vk: RollupVerifyingKey::SP1VerifyingKey(Buf32::zero()),
            dispatch_assignment_dur: 100,
            proof_publish_mode: ProofPublishMode::Strict,
            max_deposits_in_block: 10,
            network: args.network,
        },
        run: SyncParams {
            l1_follow_distance: 10,
            client_checkpoint_interval: 200,
            l2_blocks_fetch_limit: 100,
        },
    };
    info!(?rollup_params, "constructed rollup params");
    EnvelopeConfig::new(
        Arc::new(rollup_params),
        args.sequencer_address.clone(),
        args.network,
        args.fee_rate,
        546,
    )
}

fn derive_schnorr_pubkey(seckey: &Buf32) -> Buf32 {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(seckey.as_ref()).expect("Invalid private key");
    let keypair = secret_key.keypair(&secp);
    let (pubkey, _parity) = keypair.x_only_public_key();
    Buf32::from(pubkey.serialize())
}
