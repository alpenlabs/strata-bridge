//! Build script for the SP1 `guest-bridge-proof` ELF.
//!
//! Active only in `--release` **and** with the `build-elf` feature enabled.
//! Reads `BRIDGE_PROOF_ASM_PARAMS_PATH`, `BRIDGE_PROOF_ASM_VK_PATH`, and
//! `BRIDGE_PROOF_MOHO_VK_PATH` (or `stub/` files under `SKIP_PARAMS=1`),
//! writes the SSZ-encoded `BridgeProofGenesis` to
//! `guest-bridge-proof/build/genesis.bin`, and compiles the SP1 guest ELF
//! directly into `<crate>/elfs/bridge-proof.elf` (referenced at runtime via
//! [`strata_bridge_sp1_guest_builder::BRIDGE_PROOF_ELF_PATH`]).
//!
//! In `dev` profile, or whenever `build-elf` is inactive, the script is a
//! no-op — and the heavy SP1 host stack stays out of the build-dependency
//! graph entirely. Consumers of `BRIDGE_PROOF_ELF_PATH` see whatever a prior
//! release build left in `elfs/` (potentially stale or missing).

fn main() {
    #[cfg(all(not(debug_assertions), feature = "build-elf"))]
    release::run();
}

#[cfg(all(not(debug_assertions), feature = "build-elf"))]
mod release {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use sp1_build::{build_program_with_args, BuildArgs};
    use ssz::Encode;
    use strata_bridge_proof::{
        load_genesis_from_paths, sp1_groth16_predicate_string, ASM_PARAMS_PATH_ENV,
        ASM_VK_PATH_ENV, MOHO_VK_PATH_ENV,
    };

    const SKIP_PARAMS_ENV: &str = "SKIP_PARAMS";
    const STUB_ASM_PARAMS: &str = "stub/asm-params.json";
    const STUB_ASM_VK: &str = "stub/asm-vk.json";
    const STUB_MOHO_VK: &str = "stub/moho-vk.json";
    const GUEST_DIR: &str = "guest-bridge-proof";
    const ELF_NAME: &str = "bridge-proof.elf";
    const PREDICATE_NAME: &str = "bridge-proof.predicate";
    const ELFS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs");

    pub fn run() {
        println!("cargo:rerun-if-env-changed=SP1_SKIP_PROGRAM_BUILD");
        println!("cargo:rerun-if-env-changed={SKIP_PARAMS_ENV}");
        println!("cargo:rerun-if-env-changed={ASM_PARAMS_PATH_ENV}");
        println!("cargo:rerun-if-env-changed={ASM_VK_PATH_ENV}");
        println!("cargo:rerun-if-env-changed={MOHO_VK_PATH_ENV}");

        // Mirror sp1-build's own skip predicates so `SP1_SKIP_PROGRAM_BUILD=true` and
        // `cargo clippy --release` work without provisioning input JSONs.
        if sp1_build_will_skip() {
            return;
        }

        let build_out_dir = Path::new(GUEST_DIR).join("build");
        let genesis_out_file = build_out_dir.join("genesis.bin");

        let skip = std::env::var_os(SKIP_PARAMS_ENV).is_some();
        let asm_params_path = resolve_input(ASM_PARAMS_PATH_ENV, STUB_ASM_PARAMS, skip);
        let asm_vk_path = resolve_input(ASM_VK_PATH_ENV, STUB_ASM_VK, skip);
        let moho_vk_path = resolve_input(MOHO_VK_PATH_ENV, STUB_MOHO_VK, skip);

        println!("cargo:rerun-if-changed={}", asm_params_path.display());
        println!("cargo:rerun-if-changed={}", asm_vk_path.display());
        println!("cargo:rerun-if-changed={}", moho_vk_path.display());

        fs::create_dir_all(&build_out_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", build_out_dir.display()));

        let genesis = load_genesis_from_paths(&asm_params_path, &asm_vk_path, &moho_vk_path);
        // Surface the genesis baked into this ELF; it pins the trust anchors the guest verifies
        // against.
        println!("cargo:warning=bridge-proof ELF baking in genesis: {genesis:?}");
        fs::write(&genesis_out_file, genesis.as_ssz_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", genesis_out_file.display()));

        let build_args = BuildArgs {
            output_directory: Some(ELFS_DIR.to_owned()),
            elf_name: Some(ELF_NAME.to_owned()),
            #[cfg(feature = "docker-build")]
            docker: true,
            #[cfg(feature = "docker-build")]
            workspace_directory: Some("../../".to_owned()),
            ..BuildArgs::default()
        };

        build_program_with_args(GUEST_DIR, build_args);

        // Emit the on-chain predicate identity for the freshly built ELF alongside it.
        // Operators load this `Sp1Groth16:<hex>` string into their consensus params so the
        // network actually verifies the Groth16-wrapped bridge proofs this guest produces.
        let elf_path = Path::new(ELFS_DIR).join(ELF_NAME);
        let elf = fs::read(&elf_path)
            .unwrap_or_else(|e| panic!("read built ELF {}: {e}", elf_path.display()));
        let predicate = sp1_groth16_predicate_string(&elf)
            .unwrap_or_else(|e| panic!("derive sp1 groth16 predicate: {e}"));
        let predicate_out_file = Path::new(ELFS_DIR).join(PREDICATE_NAME);
        fs::write(&predicate_out_file, predicate)
            .unwrap_or_else(|e| panic!("write {}: {e}", predicate_out_file.display()));
    }

    fn resolve_input(env_var: &str, stub_path: &str, skip: bool) -> PathBuf {
        if skip {
            PathBuf::from(stub_path)
        } else {
            std::env::var_os(env_var)
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    panic!(
                        "{env_var} must be set (or set SKIP_PARAMS=1 to use bundled stubs from stub/)"
                    )
                })
        }
    }

    fn sp1_build_will_skip() -> bool {
        let skip_env = std::env::var("SP1_SKIP_PROGRAM_BUILD")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let is_clippy = std::env::var("RUSTC_WORKSPACE_WRAPPER")
            .map(|v| v.contains("clippy-driver"))
            .unwrap_or(false);
        skip_env || is_clippy
    }
}
