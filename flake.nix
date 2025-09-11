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
        alpen-bridge-toml = builtins.fromTOML (builtins.readFile ./bin/alpen-bridge/Cargo.toml);
      in
      rec {
        packages = {
          default = packages.alpen-cli;

          alpen-cli = pkgs.rustPlatform.buildRustPackage {
            pname = alpen-bridge-toml.package.name;
            version = alpen-bridge-toml.package.version;
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };
            buildType = "release";
            doCheck = false;
            cargoBuildFlags = [
              "--package"
              "alpen-bridge"
              "--bin"
              "alpen-bridge"
            ];
            nativeBuildInputs = with pkgs; [
              pkg-config
              rust-toolchain
            ];
            buildInputs = with pkgs; [
              openssl
            ];
            meta = {
              mainProgram = "alpen";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            openssl

            # rust
            rust-toolchain

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
            protobuf # TODO(@zk2u): remove after strata-p2p V2

            # C/C++ build dependencies for bindgen and native libs
            pkg-config
            clang
            llvmPackages.libclang.lib
            llvmPackages.libcxxStdenv.cc.cc.lib
            stdenv.cc.cc.lib
          ];

          env = {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.llvmPackages.libcxxStdenv.cc.cc.lib}/lib";
          };

          # Fix jemalloc-sys build error on nixos
          hardeningDisable = [ "all" ];
        };
      }
    );
}
