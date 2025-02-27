# Strata Bridge Proof of Concept

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![codecov](https://codecov.io/github/alpenlabs/strata-bridge/graph/badge.svg?token=UYZ5YPKGL2)](https://codecov.io/github/alpenlabs/strata-bridge)
[![build](https://github.com/alpenlabs/strata-bridge/actions/workflows/build.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-bridge/actions)
[![lint](https://github.com/alpenlabs/strata-bridge/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-bridge/actions)

A research implementation of Strata Bridge by your friends at [Alpen Labs](https://www.alpenlabs.io/).

> [!IMPORTANT]
> The majority of this code was written in a two-week period in a hackathon spirit.
> This software was written as a research proof of concept, and is _not_ meant to be used in a production environment!

## Transaction Graph

The following is the transaction graph that has been implemented in this repository:

<figure>
    <img src="./assets/poc-tx-graph.jpg" alt = "Transaction graph" />
    <figcaption>The transaction graph for this repository, focussing on the non-optimistic path.</figcaption>
</figure>

## System Diagram

The following is the system diagram for this repository:

<figure>
    <img src="./assets/system-design.jpg" alt = "System diagram" />
    <figcaption>The system diagram for this repository.</figcaption>
</figure>

## How To Run Locally

### Prerequisites

-   [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
-   [SP1 Toolchain](https://docs.succinct.xyz/docs/sp1/getting-started/install) and associated [linkers](https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/tag/v14.2.0-2).
-   Credentials to connect to SP1's [infra](https://explorer.succinct.xyz).
-   [Docker](https://docs.docker.com/get-docker/).
-   [`sqlx-cli`](https://lib.rs/crates/sqlx-cli) to run database migrations.

### Running

Run the Strata stack (`strata-client`, `strata-reth`, `bitcoind`) as per the instructions
in the [`strata`](https://github.com/alpenlabs/strata/tree/bitvm2) repository. Then run:

```bash
make migrate
PROFILE=release make run
```

In order to perform deposits and withdrawals, you can run:

```bash
make bridge-in
make bridge-out
```

The above `Makefile` recipes have defaults for `strata-client` and `bitcoind`.

## Contributing

Contributions are generally welcome.
If you intend to make larger changes, please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
