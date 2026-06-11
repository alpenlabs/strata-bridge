# Opt-in SP1 proving mode: build the guest ELF and enable the `sp1` feature on the bridge
# node. The mock-vs-real choice is driven entirely by SP1_PROVER, which every operator's
# bridge node inherits from this exported env:
#   - unset / "mock": fast mock proofs (default; no real proving)
#   - "cpu" / "cuda" / "network": real SP1 proving (much slower)
#
# With external bitcoin, generate asm-params from the live L1 (mining to genesis height)
# and bake them into the ELF so proofs verify against the actual chain; otherwise build
# with bundled stub params.
#
# Sourced from run_test.sh after `pushd ..`: expects CWD = repo root and consumes the
# parent shell's `extract_cargo_rev` helper plus `$ASM_REV`.
BRIDGE_FEATURES=""
if [ "$BRIDGE_PROOF_SP1" = "1" ]; then
    export SP1_PROVER="${SP1_PROVER:-mock}"
    if [ "$BRIDGE_EXTERNAL_BITCOIN" = "1" ]; then
        export BRIDGE_PROOF_ASM_PARAMS_DIR="$(realpath functional-tests)/_asm_params"
        mkdir -p "$BRIDGE_PROOF_ASM_PARAMS_DIR"
        export BRIDGE_PROOF_NUM_OPERATORS="${BRIDGE_PROOF_NUM_OPERATORS:-2}"

        # Opt-in: real SP1 Groth16 ASM+Moho proving. Build the asm/moho guest ELFs at the
        # pinned asm rev, derive their Sp1Groth16 predicates, and (later) point the
        # asm-runner at the ELFs. Without this, the asm-runner signs native Schnorr
        # attestations and the vk files stay Bip340Schnorr.
        if [ "$BRIDGE_PROOF_SP1_ASM" = "1" ]; then
            ASM_SRC="$(realpath functional-tests)/.asm-src"
            if [ "$(git -C "$ASM_SRC" rev-parse HEAD 2>/dev/null)" != "$ASM_REV" ]; then
                rm -rf "$ASM_SRC"
                git clone https://github.com/alpenlabs/asm "$ASM_SRC"
                git -C "$ASM_SRC" checkout "$ASM_REV"
            fi
            echo "Building ASM/Moho SP1 guest ELFs (asm rev $ASM_REV); this is slow"
            # The asm guest-builder compiles C deps for the riscv guest target; point AR at
            # the succinct toolchain's llvm-ar so cross-compilation finds a compatible archiver.
            SP1_AR="$(rustc +succinct --print sysroot)/lib/rustlib/$(rustc +succinct -vV | sed -n 's/^host: //p')/bin/llvm-ar"
            export AR="$SP1_AR"
            export AR_riscv64im_unknown_none_elf="$SP1_AR"
            ( cd "$ASM_SRC" && cargo build --release -p strata-asm-sp1-guest-builder )
            export BRIDGE_PROOF_ASM_ELF_PATH="$ASM_SRC/guest-builder/sp1/elfs/asm.elf"
            export BRIDGE_PROOF_MOHO_ELF_PATH="$ASM_SRC/guest-builder/sp1/elfs/moho.elf"

            # Derive the Sp1Groth16 predicates the bridge proof verifies against. These
            # match the asm-runner's own (shared sp1 6.2.0 / zkaleido v0.1-beta.2).
            cargo build --release -p proof-datatool --features sp1
            export BRIDGE_PROOF_SP1_ASM_PREDICATE="$(target/release/proof-datatool sp1-predicate "$BRIDGE_PROOF_ASM_ELF_PATH")"
            export BRIDGE_PROOF_SP1_MOHO_PREDICATE="$(target/release/proof-datatool sp1-predicate "$BRIDGE_PROOF_MOHO_ELF_PATH")"
            echo "ASM predicate:  $BRIDGE_PROOF_SP1_ASM_PREDICATE"
            echo "MOHO predicate: $BRIDGE_PROOF_SP1_MOHO_PREDICATE"
        fi

        # Also pre-funds operator general wallets so ASM genesis anchors at the
        # post-funded tip.
        echo "SP1 proving mode (SP1_PROVER=$SP1_PROVER): pre-funding operators and generating asm-params from external L1 $BITCOIN_RPC_URL"
        ( cd functional-tests && uv run python gen_asm_params_external.py )
        export BRIDGE_PROOF_ASM_PARAMS_PATH="$BRIDGE_PROOF_ASM_PARAMS_DIR/asm-params.json"
        export BRIDGE_PROOF_ASM_VK_PATH="$BRIDGE_PROOF_ASM_PARAMS_DIR/asm-vk.json"
        export BRIDGE_PROOF_MOHO_VK_PATH="$BRIDGE_PROOF_ASM_PARAMS_DIR/moho-vk.json"
        cargo build --release -p strata-bridge-sp1-guest-builder --features build-elf
    else
        echo "SP1 proving mode (SP1_PROVER=$SP1_PROVER): building guest ELF with stub params (may take several minutes)"
        SKIP_PARAMS=1 cargo build --release -p strata-bridge-sp1-guest-builder --features build-elf
    fi
    BRIDGE_FEATURES="--features sp1"
    export BRIDGE_PROOF_SP1_ELF="$(realpath guest-builder/sp1/elfs/bridge-proof.elf)"
    export BRIDGE_COUNTERPROOF_SP1_ELF="$(realpath guest-builder/sp1/elfs/counterproof.elf)"
    echo "SP1 ELF (bridge-proof):  $BRIDGE_PROOF_SP1_ELF (SP1_PROVER=$SP1_PROVER)"
    echo "SP1 ELF (counterproof): $BRIDGE_COUNTERPROOF_SP1_ELF"
    if [ -n "$MOSAIC_CIRCUIT_PATH" ]; then
        echo "Mosaic circuit: $MOSAIC_CIRCUIT_PATH"
    fi
fi
