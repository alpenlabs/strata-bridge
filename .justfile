# Variables
git_tag := `git describe --tags --abbrev=0 2>/dev/null || echo "no-tag"`
timestamp := `date +%s`
build_path := "target"
docker_dir := "docker"
docker_datadir := "data"
profile := env("PROFILE", "dev")
cargo_install_extra_flags := env("CARGO_INSTALL_EXTRA_FLAGS", "")
features := env("FEATURES", "")
docker_image_name := env("DOCKER_IMAGE_NAME", "")
unit_test_args := "--locked --workspace --profile ci --retries 2 --status-level fail --no-capture"
cov_file := "lcov.info"

# Default recipe - show available commands
default:
    @just --list

# Build the workspace into the `target` directory
[group('build')]
build:
    cargo build --workspace --features "{{features}}" --profile "{{profile}}" --lib --bins --examples --tests --benches

# Run unit tests
[group('test')]
test-unit: ensure-cargo-nextest
    ZKVM_MOCK=1 cargo nextest run {{unit_test_args}}

# Run unit tests with coverage
[group('test')]
cov-unit: ensure-cargo-llvm-cov ensure-cargo-nextest
    rm -f {{cov_file}}
    cargo llvm-cov nextest --lcov --output-path {{cov_file}} {{unit_test_args}}

# Generate an HTML coverage report and open it in the browser
[group('test')]
cov-report-html: ensure-cargo-llvm-cov ensure-cargo-nextest
    cargo llvm-cov --open nextest {{unit_test_args}}

# Runs `nextest` under `cargo-mutants`. Caution: This can take *really* long to run
[group('test')]
mutants-test: ensure-cargo-mutants
    cargo mutants --workspace -j2

# Check for security advisories on any dependencies
[group('test')]
sec: ensure-cargo-audit
    cargo audit

# cargo clean
[group('build')]
clean-cargo:
    cargo clean 2>/dev/null || true

# Remove docker data files inside /docker/data
[group('docker')]
clean-docker-data:
    rm -rf {{docker_dir}}/{{docker_datadir}} 2>/dev/null || true

# Builds the base image used to build the binaries
[group('docker')]
build-base:
    docker build -f docker/base.Dockerfile . -t bridge-base:latest

# Builds the runtime image used as the final container
[group('docker')]
build-rt:
    docker build -f docker/rt.Dockerfile . -t bridge-rt:latest

# Builds all images in the compose.yml
[group('docker')]
build-compose:
    docker compose down && docker compose up --build

# Clean docker volumes
[group('docker')]
clean:
    rm -rf docker/vol/*/data

# Cleans data and rebuilds all containers
[group('docker')]
clean-docker: build-base build-rt clean build-compose
    @echo "\n\033[36m======== DOCKER_BUILD_COMPLETE ========\033[0m\n"

# Rebuilds and starts containers without cleaning data
[group('docker')]
docker: build-base build-rt build-compose
    @echo "\n\033[36m======== DOCKER_BUILD_COMPLETE_WITH_DATA ========\033[0m\n"

# Generate TLS for secret service 1
[group('docker')]
gen-s2-tls-1:
    ./docker/gen_s2_tls.sh docker/vol/alpen-bridge-1 docker/vol/secret-service-1

# Generate TLS for secret service 2
[group('docker')]
gen-s2-tls-2:
    ./docker/gen_s2_tls.sh docker/vol/alpen-bridge-2 docker/vol/secret-service-2

# Generate TLS for secret service 3
[group('docker')]
gen-s2-tls-3:
    ./docker/gen_s2_tls.sh docker/vol/alpen-bridge-3 docker/vol/secret-service-3

# (Re)generates the TLS CAs, certs and keys for S2's and the bridge nodes to connect
[group('docker')]
gen-s2-tls: gen-s2-tls-1 gen-s2-tls-2 gen-s2-tls-3
    @echo "\n\033[36m======== TLS FILES GENERATION COMPLETE ========\033[0m\n"

# Check formatting issues but do not fix automatically
[group('code-quality')]
fmt-check-ws:
    cargo fmt --check

# Format source code in the workspace
[group('code-quality')]
fmt-ws:
    cargo fmt --all

# Check if cargo-audit is installed
[group('prerequisites')]
ensure-cargo-audit:
    #!/usr/bin/env bash
    if ! command -v cargo-audit &> /dev/null;
    then
        echo "cargo-audit not found. Please install it by running the command 'cargo install cargo-audit'"
        exit 1
    fi

# Check if cargo-llvm-cov is installed
[group('prerequisites')]
ensure-cargo-llvm-cov:
    #!/usr/bin/env bash
    if ! command -v cargo-llvm-cov &> /dev/null;
    then
        echo "cargo-llvm-cov not found. Please install it by running the command 'cargo install cargo-llvm-cov --locked'"
        exit 1
    fi

# Check if cargo-mutants is installed
[group('prerequisites')]
ensure-cargo-mutants:
    #!/usr/bin/env bash
    if ! command -v cargo-mutants &> /dev/null;
    then
        echo "cargo-mutants not found. Please install it by running the command 'cargo install cargo-mutants'"
        exit 1
    fi

# Check if cargo-nextest is installed
[group('prerequisites')]
ensure-cargo-nextest:
    #!/usr/bin/env bash
    if ! command -v cargo-nextest &> /dev/null;
    then
        echo "cargo-nextest not found. Please install it by running the command 'cargo install cargo-nextest --locked'"
        exit 1
    fi

# Check if taplo is installed
[group('prerequisites')]
ensure-taplo:
    #!/usr/bin/env bash
    if ! command -v taplo &> /dev/null; then
        echo "taplo not found. Please install it by following the instructions from: https://taplo.tamasfe.dev/cli/installation/binary.html"
        exit 1
    fi

# Runs `taplo` to check that TOML files are properly formatted
[group('code-quality')]
fmt-check-toml: ensure-taplo
    taplo fmt --check

# Runs `taplo` to format TOML files
[group('code-quality')]
fmt-toml: ensure-taplo
    taplo fmt

# Checks for lint issues in the workspace
[group('code-quality')]
lint-check-ws:
    cargo clippy \
        --workspace \
        --lib \
        --examples \
        --tests \
        --benches \
        --all-features \
        --no-deps \
        -- -D warnings

# Lints the workspace and applies fixes where possible
[group('code-quality')]
lint-fix-ws:
    cargo clippy \
        --workspace \
        --lib \
        --examples \
        --tests \
        --benches \
        --all-features \
        --fix \
        --no-deps \
        -- -D warnings

# Check if codespell is installed
[group('prerequisites')]
ensure-codespell:
    #!/usr/bin/env bash
    if ! command -v codespell &> /dev/null; then
        echo "codespell not found. Please install it by running the command 'pip install codespell' or refer to the following link for more information: https://github.com/codespell-project/codespell"
        exit 1
    fi

# Runs `codespell` to check for spelling errors
[group('code-quality')]
lint-check-codespell: ensure-codespell
    codespell

# Runs `codespell` to fix spelling errors if possible
[group('code-quality')]
lint-fix-codespell: ensure-codespell
    codespell -w

# Lints TOML files
[group('code-quality')]
lint-check-toml: ensure-taplo
    taplo lint

# Runs all lints and checks for issues without trying to fix them
[group('code-quality')]
lint: fmt-check-ws fmt-check-toml lint-check-ws lint-check-codespell
    @echo "\n\033[36m======== OK: Lints and Formatting ========\033[0m\n"

# Runs all lints and applies fixes where possible
[group('code-quality')]
lint-fix: fmt-toml fmt-ws lint-fix-ws lint-fix-codespell
    @echo "\n\033[36m======== OK: Lints and Formatting Fixes ========\033[0m\n"

# Runs `cargo docs` to generate the Rust documents in the `target/doc` directory
[group('code-quality')]
rustdocs:
    RUSTDOCFLAGS="\
    --show-type-layout \
    --enable-index-page -Z unstable-options \
    -A rustdoc::private-doc-tests \
    -D warnings" \
    cargo doc \
    --workspace \
    --no-deps

# Runs doctests on the workspace
[group('code-quality')]
test-doc:
    cargo test --doc --workspace

# Runs all tests in the workspace including unit and docs tests
[group('code-quality')]
test: test-unit test-doc

# Runs lints (without fixing), audit, docs, and tests (run this before creating a PR)
[group('code-quality')]
pr: lint rustdocs test-doc test-unit
    @echo "\n\033[36m======== CHECKS_COMPLETE ========\033[0m\n"
    @test -z "`git status --porcelain`" || echo "WARNING: You have uncommitted changes"
    @echo "All good to create a PR!"

# Run migrations
[group('database')]
migrate:
    #!/usr/bin/env bash
    export DATABASE_URL="sqlite://./operator.db"
    rm -f operator.db
    touch operator.db
    sqlx migrate run

# Broadcast a mock checkpoint
[group('bridge')]
checkpoint:
    RUST_LOG=info \
    cargo r \
        --bin mock-checkpoint \
        -- \
        --btc-url http://localhost:18443/wallet/default \
        --btc-user user \
        --btc-pass password \
        --checkpoint-tag strata-ckpt \
        --deposit-entries deposit-entries.json \
        --sequencer-xpriv tprv8ezKDhpQHojBcUwXVZHBHBMg3QJQieAneQt9kkSMBoxdWdfBi1oBTiDev4J1ebeWH9hVV64fDeddyaLjMe7tjuS16QKPwykFAAiM66RcZWi # keep this in sync with `docker/vol/alpen-bridge-{1,2,3}/params.toml`

# Run bridge-in
[group('bridge')]
bridge-in:
    RUST_LOG=info \
    cargo r \
        --bin dev-cli \
        -- \
        bridge-in \
        --btc-url http://localhost:18443/wallet/default \
        --btc-user user \
        --btc-pass password \
        --params bin/dev-cli/params.toml \
        --ee-address 70997970C51812dc3A010C7d01b50e0d17dc79C8 # from anvil #2

# Run bridge-out
[group('bridge')]
bridge-out:
    RUST_LOG=info \
    cargo r \
        --bin dev-cli \
        -- \
        bridge-out \
        --params bin/dev-cli/params.toml \
        --ee-url http://localhost:8545 \
        --destination-address-pubkey 94b25feb390fbefadd68f7c1eee7e0c475fea0d1fdde59ba66ab6ca819fce47c \
        --private-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d # from anvil #2

# Issue a challenge transaction, set `CLAIM_TXID` env var to use
[group('bridge')]
challenge:
    RUST_LOG=info \
    cargo r \
        --bin dev-cli \
        -- \
        challenge \
        --btc-url http://localhost:18443/wallet/default \
        --btc-user user \
        --btc-pass password \
        --params bin/dev-cli/params.toml \
        --bridge-node-url http://localhost:15678/rpc

# Issue a disprove transaction, set `POST_ASSERT_TXID` env var to use and make sure `strata-bridge-groth16-vk.hex` file exists
[group('bridge')]
disprove:
    RUST_LOG=info \
    cargo r \
        --bin dev-cli \
        -- \
        disprove \
        --btc-url http://localhost:18443/wallet/default \
        --btc-user user \
        --btc-pass password \
        --params bin/dev-cli/params.toml \
        --vk-path strata-bridge-groth16-vk.hex \
        --bridge-node-url http://localhost:15678/rpc

[doc("\
Performs the following experiment:
1. Make a deposit request and stop the nodes after the contract is created but before the graphs can be generated.
2. Delete the deposit setup for operator 0 from the network state.
3. Start all but the first node again.
4. Wait for the nodes to sync.
5. Make a few more deposits that the first node misses out on and wait till they are buried.
6. Start the first node again and check if all deposits make it through.\
")]
[group('experiments')]
erase-deposit-setup:
    #!/usr/bin/env bash -xe
    just bridge-in
    sleep 15 # wait for graph generation to begin
    docker compose stop bridge-{1,2,3}
    sleep 5 # wait for nodes to stop
    sqlite3 docker/vol/alpen-bridge-1/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx=1;"
    sqlite3 docker/vol/alpen-bridge-2/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx=1 and operator_idx=0;"
    sqlite3 docker/vol/alpen-bridge-3/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx=1 and operator_idx=0;"
    docker compose start bridge-{2,3}
    sleep 10 # wait for nodes to sync
    for i in {1..3}; do
        just bridge-in
    done
    sleep 10 # wait for deposits to be buried
    docker compose start bridge-1

[group('experiments')]
[doc("\
Simulates the following scenario:
- Nodes crash after persisting new contract(s) but before persisting the deposit setup.
- The nodes stay down long enough for the contract(s) to be `Aborted`.
- The nodes also miss a few deposit requests while they're down.

Manual steps required before running this recipe:
1. Make at least four deposits (0,1,2,3 - 2 and 3 will be leaked by this recipe).
2. Make at least two more concurrent deposits (but stop the nodes before two deposit goes through).
3. Update the `block_height` in the sql statements in this recipe to match the last processed block height before stopping the nodes.\
")]
leak-deposit-setup:
    #!/usr/bin/env bash -xe
    sqlite3 docker/vol/alpen-bridge-1/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx>=2 and deposit_idx<=3"
    sqlite3 docker/vol/alpen-bridge-1/data/bridge.db "UPDATE contracts SET state = '{\"block_height\":180,\"state\":\"Aborted\"}' where deposit_idx>=2 and deposit_idx<=3"
    sqlite3 docker/vol/alpen-bridge-2/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx>=2 and deposit_idx<=3"
    sqlite3 docker/vol/alpen-bridge-2/data/bridge.db "UPDATE contracts SET state = '{\"block_height\":180,\"state\":\"Aborted\"}' where deposit_idx>=2 and deposit_idx<=3"
    sqlite3 docker/vol/alpen-bridge-3/data/bridge.db "DELETE FROM operator_stake_data WHERE deposit_idx>=2 and deposit_idx<=3"
    sqlite3 docker/vol/alpen-bridge-3/data/bridge.db "UPDATE contracts SET state = '{\"block_height\":180,\"state\":\"Aborted\"}' where deposit_idx>=2 and deposit_idx<=3"
    for i in {1..2}; do
        just bridge-in
    done
    sleep 10
    docker compose start bridge-{1,2,3}
