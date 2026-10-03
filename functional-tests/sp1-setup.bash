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
# Sourced from run_test.sh after `pushd ..`: expects CWD = repo root and consumes `$ASM_REF`.

# Downloads <guest>.elf from the alpenlabs/<guest> release <tag> into $GUEST_ELFS_DIR, checks
# it against the release's SHA256SUMS, logs its sha256, and prints its path.
fetch_release_elf() {
    local guest="$1" ref_type="$2" tag="$3"
    if [ "$ref_type" != "tag" ]; then
        echo "ERROR: $guest is pinned by $ref_type $tag; release ELFs need a tag pin" >&2
        return 1
    fi
    local dir="$GUEST_ELFS_DIR/$guest-$tag"
    local url="https://github.com/alpenlabs/$guest/releases/download/$tag"
    mkdir -p "$dir"
    for file in "$guest.elf" SHA256SUMS; do
        curl -fsSL --proto "=https" --retry 5 --retry-delay 5 --retry-all-errors \
            -o "$dir/$file" "$url/$file" || return 1
    done
    # Command substitution drops `set -e`, so each failure has to return explicitly.
    ( cd "$dir" && grep "  $guest.elf\$" SHA256SUMS | shasum -a 256 -c - ) >&2 || return 1
    echo "$guest.elf ($tag) sha256: $(shasum -a 256 "$dir/$guest.elf" | cut -d' ' -f1)" >&2
    echo "$dir/$guest.elf"
}

BRIDGE_FEATURES=""
if [ "$BRIDGE_PROOF_SP1" = "1" ]; then
    export SP1_PROVER="${SP1_PROVER:-mock}"
    # The guests bake the Moho genesis in, so they must match the asm-runner's genesis spec
    # (`ASM_SPEC_ID` in constants.py).
    export BRIDGE_PROOF_ASM_GENESIS_SPEC_ID=1
    if [ "$BRIDGE_EXTERNAL_BITCOIN" = "1" ]; then
        export BRIDGE_PROOF_ASM_PARAMS_DIR="$(realpath functional-tests)/_asm_params"
        mkdir -p "$BRIDGE_PROOF_ASM_PARAMS_DIR"
        export BRIDGE_PROOF_NUM_OPERATORS="${BRIDGE_PROOF_NUM_OPERATORS:-2}"

        # Opt-in: real SP1 Groth16 ASM+Moho proving. Fetch the asm/moho guest ELFs from the
        # releases of the pinned asm/moho tags, derive their Sp1Groth16 predicates, and (later)
        # point the asm-runner at the ELFs. Without this, the asm-runner signs native Schnorr
        # attestations and the vk files stay Bip340Schnorr.
        if [ "$BRIDGE_PROOF_SP1_ASM" = "1" ]; then
            read -r MOHO_REF_TYPE MOHO_REF < <(extract_cargo_git_ref moho-types)
            GUEST_ELFS_DIR="$(realpath functional-tests)/.guest-elfs"
            BRIDGE_PROOF_ASM_ELF_PATH="$(fetch_release_elf asm "$ASM_REF_TYPE" "$ASM_REF")"
            BRIDGE_PROOF_MOHO_ELF_PATH="$(fetch_release_elf moho "$MOHO_REF_TYPE" "$MOHO_REF")"
            export BRIDGE_PROOF_ASM_ELF_PATH BRIDGE_PROOF_MOHO_ELF_PATH

            # Derive the Sp1Groth16 predicates the bridge proof verifies against. These
            # match the asm-runner's own, which it derives from the same ELFs.
            cargo build --release -p proof-datatool --features sp1
            # Assign before exporting so a failed derivation trips `set -e`.
            BRIDGE_PROOF_SP1_ASM_PREDICATE="$(target/release/proof-datatool sp1-predicate "$BRIDGE_PROOF_ASM_ELF_PATH")"
            BRIDGE_PROOF_SP1_MOHO_PREDICATE="$(target/release/proof-datatool sp1-predicate "$BRIDGE_PROOF_MOHO_ELF_PATH")"
            export BRIDGE_PROOF_SP1_ASM_PREDICATE BRIDGE_PROOF_SP1_MOHO_PREDICATE
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
fi
