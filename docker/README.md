# Bridge docker setup

For all images, build from the strata-bridge directory with:

```sh
docker build -f docker/<dockerfile> .
```

Layout:

- `Dockerfile`: base image used to build the other images.

## Base image

- x86 ubuntu 24.04 image based on succinct's SP1 image
- SP1 toolchain installed
- Bridge toolchain installed
- External dependencies compiled
- Internal dependencies (`crates` dir) compiled

Build using:

```sh
docker build -f docker/base.Dockerfile . -t bridge-base:latest
```

## Runtime image

- x86 ubuntu 24.04 image updated, upgraded and cleaned

```sh
docker build -f docker/rt.Dockerfile . -t bridge-rt:latest
```

## Running locally

Bridge operators can be run locally via containers. However, these require some configurations and parameters to be set up.

### Pre-requisites

To run three bridge operators (one bridge node and one secret service node each), you need to first generate the required tls certificates and seeds.
You can do this with:

```sh
just gen-s2-tls
```

This will create the required files/directories inside `docker/vol/alpen-bridge-{1,2,3}`.

### Running the containers

```sh
just clean-docker
```

This will build the base and runtime images, clean up the database in `docker/vol`, delete old containers and run new ones.

### Updating params and entrypoint script

When running the containers for the first time, the bridge nodes and the bitcoind node will crash.
This is because the params file have not been configured properly for the bridge node and
the appropriate addresses are not configured in the [entrypoint.sh](./bitcoin/entrypoint.sh) script.
However, before crashing, these nodes will log some useful information.

To update the [params](./vol/alpen-bridge-1/params.toml) file, you need to get the p2p and musig2 public keys for each operator from the container logs.
The logs should look something like the following:

```plaintext
2025-04-15T10:07:12.971503Z  INFO alpen_bridge::mode::operator: bin/alpen-bridge/src/mode/operator.rs:82: Retrieved P2P public key from S2 p2p_pk=020b1251c1a11d65a3cf324c66b67e9333799d21490d2e2c95866aab76e3a0f301
2025-04-15T10:07:12.972824Z  INFO alpen_bridge::mode::operator: bin/alpen-bridge/src/mode/operator.rs:85: Retrieved MuSig2 operator key from S2 my_btc_pk=b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d
```

Use these values to populate the `keys` section of the params file. You also need to update the `wallet_pk` value in the sidesystem params.

**Important**: The order of these values matters in the params file as well as in the sidesystem config! The `[sidesystem]` value should be exactly the same as the strata's rollup params. Note that **signing pks are obsolete**, so they can be set to any valid schnorr pubkeys.

Similarly, you can get the general and stake chain wallet addresses for each operator from the logs.
These should look like the following:

```plaintext
2025-04-15T10:07:13.045585Z  INFO operator_wallet: crates/operator-wallet/src/lib.rs:87: general wallet address: bcrt1pjsz8n98943w6h7tn0gtk7rrea6ulp8yhfxsg0gfcmkcl709vavhs5qpe8y
2025-04-15T10:07:13.046028Z  INFO operator_wallet: crates/operator-wallet/src/lib.rs:95: stakechain wallet address: bcrt1payzuzxk4q2szywcnrcgyy7u0t3899xyllep92gcqsukc8r3wypxqn6qy03
```

Finally, you need to create a [`.env`](../.env) file at the root of this repository (from where you will run `just clean-docker`).
This file has the following structure:

```plaintext
GENERAL_WALLET_1=bcrt1pjsz8n98943w6h7tn0gtk7rrea6ulp8yhfxsg0gfcmkcl709vavhs5qpe8y
STAKE_CHAIN_WALLET_1=bcrt1payzuzxk4q2szywcnrcgyy7u0t3899xyllep92gcqsukc8r3wypxqn6qy03
GENERAL_WALLET_2=
STAKE_CHAIN_WALLET_2=
GENERAL_WALLET_3=
STAKE_CHAIN_WALLET_3=
SP1_PROVER=network
SP1_PROOF_STRATEGY=
NETWORK_RPC_URL=
NETWORK_PRIVATE_KEY=
```
> Make sure to have `SP1_PROOF_STRATEGY`, `NETWORK_RPC_URL` and `NETWORK_PRIVATE_KEY` properly set as these are needed during bridging-in.

### Memory Profiling

The bridge operators and secret services are built with memory profiling enabled using `jemalloc`. This feature exposes HTTP endpoints for heap profiling on port `3000` for each service.

The following ports are mapped for memory profiling:

- Bridge node 1: `localhost:13000` → container port `3000`
- Bridge node 2: `localhost:23000` → container port `3000`
- Bridge node 3: `localhost:33000` → container port `3000`
- Secret service 1: `localhost:11000` → container port `3000`
- Secret service 2: `localhost:21000` → container port `3000`
- Secret service 3: `localhost:31000` → container port `3000`

Available endpoints:

- `/debug/pprof/heap` - Raw heap profile data (`pprof` format)
- `/debug/pprof/heap/flamegraph` - Heap profile as SVG flamegraph

Example usage:

```sh
# Get heap profile for bridge node 1
curl http://localhost:13000/debug/pprof/heap > bridge1-heap.pprof

# View flamegraph for secret service 1 in browser
open http://localhost:11000/debug/pprof/heap/flamegraph
```

### Bridging in

To bridge-in, you can run:

```sh
just bridge-in
```

**Important:** Ensure that the musig2 keys used in dev-cli parameters match those used in bridge operator parameters for consistency.

## Troubleshooting

### SP1 Build Errors

If you encounter SP1 verification errors during `just bridge-in` similar to:

```
error: failed to run custom build command for `sp1-prover v5.0.5`
thread 'main' panicked at build.rs:59:47:
called `Result::unwrap()` on an `Err` value: Verification(...vk_map.bin: (verification: FAILED))
```

This typically indicates an issue with the SP1 toolchain setup. Ensure you have:

1. Installed the SP1 toolchain: `curl -L https://sp1up.succinct.xyz | bash`  
2. Completed the setup by running: `sp1up`
3. Restarted your terminal or sourced your shell configuration

If the error persists after proper SP1 setup, verify that your `.env` file contains the correct SP1 configuration as shown above.
