{
  description = "Strata Bridge Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    sp1-nix = {
      url = "github:alpenlabs/sp1.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    risc0-nix = {
      url = "github:alpenlabs/risc0.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      sp1-nix,
      risc0-nix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            rust-overlay.overlays.default
            sp1-nix.overlays.default
            risc0-nix.overlays.default
          ];
        };
        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Create a shadow SP1 sysroot with our custom rustc
        sp1-shadow-sysroot = pkgs.runCommand "sp1-shadow-sysroot" { } ''
          # Copy the entire SP1 sysroot structure
          cp -r ${pkgs.sp1-rust-toolchain} $out
          chmod -R u+w $out

          # Replace the rustc binary with a direct link to SP1 rustc
          rm $out/bin/rustc
          ln -s ${pkgs.sp1-rust-toolchain}/bin/rustc $out/bin/rustc
        '';

        # Create a cargo wrapper that handles the --lib issue
        cargo-wrapper = pkgs.writeShellScriptBin "cargo" ''
          # Check if this is a workspace --lib build
          if [[ "$*" == *"--workspace"* ]] && [[ "$*" == *"--lib"* ]]; then
            # Extract all arguments except --lib
            args=()
            for arg in "$@"; do
              if [[ "$arg" != "--lib" ]]; then
                args+=("$arg")
              fi
            done

            # First build everything except libs
            ${rust-toolchain}/bin/cargo "''${args[@]}" && \
            # Then build libs excluding packages without lib targets
            ${rust-toolchain}/bin/cargo build --workspace --lib --locked --exclude strata-bridge-guest 2>/dev/null || true
          else
            # Normal cargo invocation
            exec ${rust-toolchain}/bin/cargo "$@"
          fi
        '';

        # Override rustc to handle +succinct toolchain syntax
        overridden-rust = pkgs.symlinkJoin {
          name = "rust-with-sp1";
          paths = [ rust-toolchain ];
          postBuild = ''
            # Remove original rustc and cargo (we provide our own cargo wrapper)
            rm $out/bin/rustc
            rm $out/bin/cargo

            # Create our custom rustc wrapper
            cat > $out/bin/rustc << 'EOF'
            #!/bin/bash

            # Handle +succinct syntax for explicit toolchain selection
            if [[ "$1" == "+succinct" ]]; then
              shift
              exec ${pkgs.sp1-rust-toolchain}/bin/rustc "$@"
            fi

            # If building lib targets, set RUSTC_WORKSPACE_WRAPPER to make SP1 skip
            if [[ "$*" == *"--crate-type lib"* ]]; then
              export RUSTC_WORKSPACE_WRAPPER="skip-sp1-for-lib"
            fi

            # Only use SP1 rustc when RUSTUP_TOOLCHAIN=succinct AND it's a toolchain query
            # This allows SP1 to find its own rustc path but doesn't interfere with compilation
            if [[ "$RUSTUP_TOOLCHAIN" == "succinct" ]]; then
              # For sysroot queries, return our shadow sysroot path instead of the real one
              if [[ "$*" == *"--print sysroot"* ]]; then
                echo "${sp1-shadow-sysroot}"
                exit 0
              fi
              # For version queries, use the real SP1 rustc
              if [[ "$*" == *"--version"* ]]; then
                exec ${pkgs.sp1-rust-toolchain}/bin/rustc "$@"
              fi
            fi

            # Check if we're compiling specifically for the SP1 target
            for arg in "$@"; do
              if [[ "$arg" == "riscv32im-succinct-zkvm-elf" ]] || [[ "$arg" == "--target=riscv32im-succinct-zkvm-elf" ]]; then
                exec ${pkgs.sp1-rust-toolchain}/bin/rustc "$@"
              fi
            done

            # Default: use standard rustc for everything else
            exec ${rust-toolchain}/bin/rustc "$@"
            EOF
            chmod +x $out/bin/rustc

            # Add rustup wrapper
            cat > $out/bin/rustup << 'EOF'
            #!/bin/bash
            if [[ "$1" == "run" && "$2" == "succinct" ]]; then
              shift 2  # remove 'run succinct'
              exec ${pkgs.sp1-rust-toolchain}/bin/"$1" "$@"
            else
              echo "rustup command not supported in Nix environment" >&2
              exit 1
            fi
            EOF
            chmod +x $out/bin/rustup
          '';
        };
        # FoundationDB is only available on Linux in nixpkgs
        fdbPackages = if pkgs.stdenv.isLinux then [ pkgs.foundationdb ] else [ ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            openssl

            # wrappers that handles SP1
            overridden-rust
            cargo-wrapper

            # zkVMs
            cargo-prove
            sp1-rust-toolchain
            risc0-toolchain

            # devtools
            git
            taplo
            codespell
            just
            cargo-nextest
            cargo-audit
            cargo-hack
            bitcoind
            sqlx-cli

            # C/C++ build dependencies for bindgen and native libs
            pkg-config
            clang
            llvmPackages.libclang.lib
            llvmPackages.libcxxStdenv.cc.cc.lib
            stdenv.cc.cc.lib
          ] ++ fdbPackages;

          env = {
            # LLVM/clang stuff
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.llvmPackages.libcxxStdenv.cc.cc.lib}/lib";

            # Skip SP1 program build both bridge-guest-builder and SP1
            SP1_SKIP_PROGRAM_BUILD = "true";
            SKIP_GUEST_BUILD = 1;

            # Force all rustc usage to go through our wrapper
            RUSTC = "${overridden-rust}/bin/rustc";
            # Also override the sysroot that SP1 might query
            RUST_SYSROOT = "${pkgs.sp1-rust-toolchain}";
          };

          # Fix jemalloc-sys build error on nixos
          hardeningDisable = [ "all" ];
        };
      }
    );
}
