//! Build script for the SP1 `guest-bridge-proof` ELF.
//!
//! Active only in `--release`. Reads `BRIDGE_PROOF_ASM_PARAMS_PATH` and
//! `BRIDGE_PROOF_MOHO_VK_PATH` (or `stub/` files under `SKIP_PARAMS=1`), writes
//! the SSZ-encoded `BridgeProofGenesis` to
//! `guest-bridge-proof/build/genesis.bin`, compiles the SP1 guest ELF, then
//! migrates the compiled ELF to a stable cache path
//! `guest-bridge-proof/build/guest-sp1-bridge-proof.elf` that
//! `bridge_proof_elf_path()` returns at runtime.
//!
//! In `dev` profile the script is a no-op — consumers of
//! `bridge_proof_elf_path()` see whatever a prior release build left in the
//! cache (potentially stale or missing).

fn main() {
    #[cfg(not(debug_assertions))]
    release::run();
}

#[cfg(not(debug_assertions))]
mod release {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use sp1_build::{build_program_with_args, BuildArgs};
    use ssz::Encode;
    use strata_bridge_proof::{
        load_genesis_from_paths, ASM_PARAMS_PATH_ENV, ASM_VK_PATH_ENV, MOHO_VK_PATH_ENV,
    };

    const SKIP_PARAMS_ENV: &str = "SKIP_PARAMS";
    const STUB_ASM_PARAMS: &str = "stub/asm-params.json";
    const STUB_ASM_VK: &str = "stub/asm-vk.json";
    const STUB_MOHO_VK: &str = "stub/moho-vk.json";
    const GUEST_DIR: &str = "guest-bridge-proof";
    const GUEST_BIN_NAME: &str = "guest-sp1-bridge-proof";
    const SP1_TARGET_TRIPLE: &str = "riscv64im-succinct-zkvm-elf";

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
        fs::write(&genesis_out_file, genesis.as_ssz_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", genesis_out_file.display()));

        #[cfg(not(feature = "docker-build"))]
        let build_args = BuildArgs::default();

        #[cfg(feature = "docker-build")]
        let build_args = BuildArgs {
            docker: true,
            workspace_directory: Some("../../".to_owned()),
            ..BuildArgs::default()
        };

        build_program_with_args(GUEST_DIR, build_args);
        migrate_elf();
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

    /// Copies the freshly compiled guest ELF from sp1-build's output directory to a stable
    /// cache path that `bridge_proof_elf_path()` resolves. No-op when sp1-build skipped the
    /// compile (e.g., `SP1_SKIP_PROGRAM_BUILD=true`) — any prior cached ELF stays in place.
    fn migrate_elf() {
        let guest_dir = Path::new(GUEST_DIR);

        let elf_subdir = if cfg!(feature = "docker-build") {
            format!("docker/{SP1_TARGET_TRIPLE}")
        } else {
            SP1_TARGET_TRIPLE.to_owned()
        };

        let src = guest_dir
            .join("target/elf-compilation")
            .join(elf_subdir)
            .join("release")
            .join(GUEST_BIN_NAME);
        let dst = guest_dir
            .join("build")
            .join(format!("{GUEST_BIN_NAME}.elf"));

        if !src.exists() {
            return;
        }

        fs::copy(&src, &dst)
            .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), dst.display()));
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
