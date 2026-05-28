//! Build script for the SP1 `guest-bridge-proof` and `guest-counterproof` ELFs.
//!
//! Active only in `--release` **and** with the `build-elf` feature enabled.
//! For `guest-bridge-proof`, reads `BRIDGE_PROOF_ASM_PARAMS_PATH`,
//! `BRIDGE_PROOF_ASM_VK_PATH`, and `BRIDGE_PROOF_MOHO_VK_PATH` (or `stub/`
//! files under `SKIP_PARAMS=1`), writes the SSZ-encoded `BridgeProofGenesis`
//! to `guest-bridge-proof/build/genesis.bin`, and compiles the SP1 guest ELF
//! directly into `<crate>/elfs/bridge-proof.elf` (referenced at runtime via
//! [`strata_bridge_sp1_guest_builder::BRIDGE_PROOF_ELF_PATH`]). The bridge-proof
//! ELF's Groth16 verifying key is then derived and threaded into the
//! `guest-counterproof` build as the `bridge_proof_vk` trust anchor, so the
//! counterproof can actually verify (and refute) embedded bridge-proof
//! receipts.
//!
//! In `dev` profile, or whenever `build-elf` is inactive, the script is a
//! no-op — and the heavy SP1 host stack stays out of the build-dependency
//! graph entirely. Consumers of the ELF path constants see whatever a prior
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
        process::Command,
    };

    use sp1_build::{build_program_with_args, BuildArgs};
    use ssz::Encode;
    use strata_bridge_counterproof::load_genesis_from_predicate;
    use strata_bridge_proof::{
        load_genesis_from_paths, ASM_PARAMS_PATH_ENV, ASM_VK_PATH_ENV, MOHO_VK_PATH_ENV,
    };
    use strata_bridge_proof_common::host::{
        sp1_groth16_predicate_key, sp1_groth16_predicate_string_from_key, sp1_program_vkey_hash,
    };
    use strata_predicate::PredicateKey;

    const SKIP_PARAMS_ENV: &str = "SKIP_PARAMS";
    const STUB_ASM_PARAMS: &str = "stub/asm-params.json";
    const STUB_ASM_VK: &str = "stub/asm-vk.json";
    const STUB_MOHO_VK: &str = "stub/moho-vk.json";
    const BRIDGE_PROOF_GUEST_DIR: &str = "guest-bridge-proof";
    const BRIDGE_PROOF_ELF_NAME: &str = "bridge-proof.elf";
    const BRIDGE_PROOF_PREDICATE_NAME: &str = "bridge-proof.predicate";
    const BRIDGE_PROOF_VKEY_NAME: &str = "bridge-proof-vkey.bin";
    const COUNTERPROOF_GUEST_DIR: &str = "guest-counterproof";
    const COUNTERPROOF_ELF_NAME: &str = "counterproof.elf";
    const COUNTERPROOF_PREDICATE_NAME: &str = "counterproof.predicate";
    const COUNTERPROOF_VKEY_NAME: &str = "counterproof-vkey.bin";
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

        // Point cc-rs (used by secp256k1-sys etc.) at the SP1 toolchain's llvm-ar, which knows
        // how to package archives for the riscv32im-succinct-zkvm-elf target. Only needed on
        // macOS — BSD `ar` produces archives that fail to link in the guest; GNU `ar` on Linux
        // is compatible.
        #[cfg(target_os = "macos")]
        export_sp1_ar();

        // 1) Build the bridge-proof guest first; its Groth16 VK is an input to the counterproof's
        //    genesis.
        write_bridge_proof_genesis();
        build_guest(BRIDGE_PROOF_GUEST_DIR, BRIDGE_PROOF_ELF_NAME);
        let bridge_proof_vk = emit_predicate(
            BRIDGE_PROOF_ELF_NAME,
            BRIDGE_PROOF_PREDICATE_NAME,
            BRIDGE_PROOF_VKEY_NAME,
        );

        // 2) Bake that VK into the counterproof guest's embedded genesis, then build.
        write_counterproof_genesis(bridge_proof_vk);
        build_guest(COUNTERPROOF_GUEST_DIR, COUNTERPROOF_ELF_NAME);
        let _ = emit_predicate(
            COUNTERPROOF_ELF_NAME,
            COUNTERPROOF_PREDICATE_NAME,
            COUNTERPROOF_VKEY_NAME,
        );
    }

    fn write_bridge_proof_genesis() {
        let build_out_dir = Path::new(BRIDGE_PROOF_GUEST_DIR).join("build");
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
    }

    fn write_counterproof_genesis(bridge_proof_vk: PredicateKey) {
        let build_out_dir = Path::new(COUNTERPROOF_GUEST_DIR).join("build");
        let genesis_out_file = build_out_dir.join("genesis.bin");

        fs::create_dir_all(&build_out_dir)
            .unwrap_or_else(|e| panic!("create {}: {e}", build_out_dir.display()));

        let genesis = load_genesis_from_predicate(bridge_proof_vk);
        println!("cargo:warning=counterproof ELF baking in genesis: {genesis:?}");
        fs::write(&genesis_out_file, genesis.as_ssz_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", genesis_out_file.display()));
    }

    fn build_guest(guest_dir: &str, elf_name: &str) {
        let build_args = BuildArgs {
            output_directory: Some(ELFS_DIR.to_owned()),
            elf_name: Some(elf_name.to_owned()),
            #[cfg(feature = "docker-build")]
            docker: true,
            #[cfg(feature = "docker-build")]
            workspace_directory: Some("../../".to_owned()),
            // Pin the docker image explicitly. sp1-build's default is
            // `concat!("v", CARGO_PKG_VERSION)` of itself, which we'd silently follow on a
            // version bump. `SP1_DOCKER_IMAGE` env var still wins if set, e.g. for a custom
            // image that pre-installs git.
            #[cfg(feature = "docker-build")]
            tag: "v6.2.0".to_owned(),
            ..BuildArgs::default()
        };

        build_program_with_args(guest_dir, build_args);
    }

    /// Derives the `Sp1Groth16:<hex>` predicate from the freshly built ELF, writes the
    /// raw 32-byte verifying-key digest and the predicate's string form next to the ELF,
    /// and returns the parsed key for the caller to thread into downstream genesis.
    fn emit_predicate(elf_name: &str, predicate_name: &str, vkey_name: &str) -> PredicateKey {
        let elf_path = Path::new(ELFS_DIR).join(elf_name);
        let elf = fs::read(&elf_path)
            .unwrap_or_else(|e| panic!("read built ELF {}: {e}", elf_path.display()));

        let vkey_hash = sp1_program_vkey_hash(&elf)
            .unwrap_or_else(|e| panic!("derive sp1 program vkey hash: {e}"));
        let vkey_out_file = Path::new(ELFS_DIR).join(vkey_name);
        fs::write(&vkey_out_file, vkey_hash)
            .unwrap_or_else(|e| panic!("write {}: {e}", vkey_out_file.display()));

        let predicate_key = sp1_groth16_predicate_key(vkey_hash)
            .unwrap_or_else(|e| panic!("derive sp1 groth16 predicate key: {e}"));
        let predicate_str = sp1_groth16_predicate_string_from_key(&predicate_key);
        let predicate_out_file = Path::new(ELFS_DIR).join(predicate_name);
        fs::write(&predicate_out_file, predicate_str)
            .unwrap_or_else(|e| panic!("write {}: {e}", predicate_out_file.display()));

        predicate_key
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

    /// Points cc-rs (used by secp256k1-sys and friends) at the SP1 toolchain's
    /// `llvm-ar` by exporting `SP1_AR`, `AR`, and `AR_riscv64im_unknown_none_elf`.
    /// The SP1 `llvm-ar` knows how to package archives for the
    /// `riscv32im-succinct-zkvm-elf` target; macOS's BSD `ar` produces archives
    /// that fail to link in the guest. Linux's GNU `ar` is compatible, so this
    /// is gated to macOS hosts only.
    #[cfg(target_os = "macos")]
    fn export_sp1_ar() {
        let sysroot = rustc_succinct(&["--print", "sysroot"]);
        let host = rustc_succinct(&["-vV"])
            .lines()
            .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
            .expect("rustc +succinct -vV must report a `host:` line");

        let sp1_ar = format!("{sysroot}/lib/rustlib/{host}/bin/llvm-ar");
        std::env::set_var("SP1_AR", &sp1_ar);
        std::env::set_var("AR", &sp1_ar);
        std::env::set_var("AR_riscv64im_unknown_none_elf", &sp1_ar);
    }

    #[cfg(target_os = "macos")]
    fn rustc_succinct(args: &[&str]) -> String {
        let output = Command::new("rustc")
            .arg("+succinct")
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("invoke `rustc +succinct {}`: {e}", args.join(" ")));
        assert!(
            output.status.success(),
            "`rustc +succinct {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("rustc stdout is utf-8")
            .trim()
            .to_owned()
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
