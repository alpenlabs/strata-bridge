// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_params::{AsmParams, SubprotocolInstance};
use strata_asm_proof_impl::statements::process_asm_stf;
use strata_asm_spec::StrataAsmSpec;
use strata_btc_types::GenesisL1View;
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
use strata_l1_txfmt::MagicBytes;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    let spec = create_spec();
    process_asm_stf(&Sp1ZkVmEnv, &spec);
}

// TODO: (@prajwolrg) Hardcoded for simplification. This needs to be addressed properly — one
// approach is to parse `AsmParams` as part of build dependencies and embed the spec at compile
// time.
fn create_spec() -> StrataAsmSpec {
    let subprotocols: Vec<SubprotocolInstance> = serde_json::from_str(
        r#"[
            {"Admin":{"strata_administrator":{"keys":["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],"threshold":1},"strata_sequencer_manager":{"keys":["03cf59a1a5ef092ced386f2651b610d3dd2cc6806bb74a8eab95c1f3b2f3d81772","02343edde4a056e00af99aa49de60df03859d1b79ebbc4f3f6da8fbd0053565de3"],"threshold":1},"confirmation_depth":144,"max_seqno_gap":10}},
            {"Checkpoint":{"sequencer_predicate":"Sp1Groth16","checkpoint_predicate":"AlwaysAccept","genesis_l1_height":3334849731,"genesis_ol_blkid":"c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"}},
            {"Bridge":{"operators":["02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"],"denomination":0,"assignment_duration":0,"operator_fee":0,"recovery_delay":0}}
          ]"#,
    )
    .expect("failed to deserialize subprotocols");

    let genesis_block = L1BlockCommitment::new(0, L1BlockId::from(Buf32::from([0u8; 32])));

    let genesis_view = GenesisL1View {
        blk: genesis_block,
        next_target: 0x1d00ffff,
        epoch_start_timestamp: 0,
        last_11_timestamps: [0u32; 11],
    };

    let params = AsmParams {
        magic: MagicBytes::new(*b"ALPN"),
        l1_view: genesis_view,
        subprotocols,
    };

    StrataAsmSpec::from_asm_params(&params)
}
