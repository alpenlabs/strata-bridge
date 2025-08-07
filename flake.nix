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
      in
      {
        # TODO: add packages.
        #       Right now it's impossible because multiple versions of the same
        #       dependency which breaks Nix's vendoring, e.g. ark-crypto-primitives,
        #       zkaleido, etc.

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            pkg-config
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
            bitcoind
            sqlx-cli
            protobuf # TODO: remove after strata-p2p V2
          ];
          shellHook = ''
            export SP1_SKIP_TARGET_INSTALL=0
          '';
        };
      }
    );
}
