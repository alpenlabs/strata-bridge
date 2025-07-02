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
    cargo build --workspace --features "{{features}}" --profile "{{profile}}"

# Run unit tests
[group('test')]
test-unit:
    -cargo install cargo-nextest --locked
    ZKVM_MOCK=1 cargo nextest run {{unit_test_args}}

# Run unit tests with coverage
[group('test')]
cov-unit:
    rm -f {{cov_file}}
    cargo llvm-cov nextest --lcov --output-path {{cov_file}} {{unit_test_args}}

# Generate an HTML coverage report and open it in the browser
[group('test')]
cov-report-html:
    cargo llvm-cov --open nextest {{unit_test_args}}

# Runs `nextest` under `cargo-mutants`. Caution: This can take *really* long to run
[group('test')]
mutants-test:
    cargo mutants --workspace -j2

# Check for security advisories on any dependencies
[group('test')]
sec:
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
        --sequencer-xpriv tprv8ezKDhpQHojBcUwXVZHBHBMg3QJQieAneQt9kkSMBoxdWdfBi1oBTiDev4J1ebeWH9hVV64fDeddyaLjMe7tjuS16QKPwykFAAiM66RcZams

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
        --ee-address 70997970C51812dc3A010C7d01b50e0d17dc79C8

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
        --private-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

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
