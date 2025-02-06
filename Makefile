# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/d599393771f9d7d137ea4abf271e1bd118184c73/Makefile
.DEFAULT_GOAL := help

GIT_TAG ?= $(shell git describe --tags --abbrev=0)
TIMESTAMP ?= $(shell date +%s)

BUILD_PATH = "target"

DOCKER_DIR = docker
DOCKER_DATADIR = data

# Cargo profile for builds. Default is for local builds, CI uses an override.
PROFILE ?= dev

# Extra flags for Cargo
CARGO_INSTALL_EXTRA_FLAGS ?=

# List of features to use for building
FEATURES ?=

# The docker image name
DOCKER_IMAGE_NAME ?=

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the workspace into the `target` directory.
	cargo build --workspace  --features "$(FEATURES)" --profile "$(PROFILE)"

##@ Test

UNIT_TEST_ARGS := --locked --workspace -E 'kind(lib)' -E 'kind(bin)' -E 'kind(proc-macro)' -F mock
COV_FILE := lcov.info

.PHONY: test-unit
test-unit: ## Run unit tests.
	-cargo install cargo-nextest --locked
	cargo nextest run $(UNIT_TEST_ARGS)

.PHONY: cov-unit
cov-unit: ## Run unit tests with coverage.
	rm -f $(COV_FILE)
	cargo llvm-cov nextest --lcov --output-path $(COV_FILE) $(UNIT_TEST_ARGS)

.PHONY: cov-report-html
cov-report-html: ## Generate an HTML coverage report and open it in the browser.
	cargo llvm-cov --open nextest $(UNIT_TEST_ARGS)

.PHONY: mutants-test
mutants-test: ## Runs `nextest` under `cargo-mutants`. Caution: This can take *really* long to run.
	cargo mutants --workspace -j2

.PHONY: sec
sec: ## Check for security advisories on any dependencies.
	cargo audit #  HACK: not denying warnings as we depend on `yaml-rust` via `format-serde-error` which is unmaintained

.PHONY: clean-cargo
clean-cargo: ## cargo clean
	cargo clean 2>/dev/null

.PHONY: clean-docker-data
clean-docker-data: ## Remove docker data files inside /docker/.data
	rm -rf $(DOCKER_DIR)/$(DOCKER_DATADIR) 2>/dev/null

.PHONY: clean
clean: clean-docker-data clean-cargo ## clean functional tests directory, cargo clean, clean docker data
	@echo "\n\033[36m======== CLEAN_COMPLETE ========\033[0m\n"

.PHONY: docker-up
docker-up: ## docker compose up
	cd $(DOCKER_DIR) && docker compose up -d

.PHONY: docker-down
docker-down: ## docker compose down
	cd $(DOCKER_DIR) && docker compose down && \
	rm -rf $(DOCKER_DIR)/$(DOCKER_DATADIR) 2>/dev/null

##@ Code Quality

.PHONY: fmt-check-ws
fmt-check-ws: ## Check formatting issues but do not fix automatically.
	cargo fmt --check

.PHONY: fmt-ws
fmt-ws: ## Format source code in the workspace.
	cargo fmt --all

.PHONY: ensure-taplo
ensure-taplo:
	@if ! command -v taplo &> /dev/null; then \
		echo "taplo not found. Please install it by following the instructions from: https://taplo.tamasfe.dev/cli/installation/binary.html" \
		exit 1; \
    fi

.PHONY: fmt-check-toml
fmt-check-toml: ensure-taplo ## Runs `taplo` to check that TOML files are properly formatted
	taplo fmt --check

.PHONY: fmt-toml
fmt-toml: ensure-taplo ## Runs `taplo` to format TOML files
	taplo fmt

.PHONY: lint-check-ws
lint-check-ws: ## Checks for lint issues in the workspace.
	cargo clippy \
	--workspace \
	 \
	--lib \
	--examples \
	--tests \
	--benches \
	--all-features \
	--no-deps \
	-- -D warnings

.PHONY: lint-fix-ws
lint-fix-ws: ## Lints the workspace and applies fixes where possible.
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

ensure-codespell:
	@if ! command -v codespell &> /dev/null; then \
		echo "codespell not found. Please install it by running the command 'pip install codespell' or refer to the following link for more information: https://github.com/codespell-project/codespell" \
		exit 1; \
    fi

.PHONY: lint-codespell
lint-check-codespell: ensure-codespell ## Runs `codespell` to check for spelling errors.
	codespell

.PHONY: lint-fix-codespell
lint-fix-codespell: ensure-codespell ## Runs `codespell` to fix spelling errors if possible.
	codespell -w

.PHONY: lint-toml
lint-check-toml: ensure-taplo ## Lints TOML files
	taplo lint

.PHONY: lint
lint: fmt-check-ws fmt-check-toml lint-check-ws lint-check-codespell ## Runs all lints and checks for issues without trying to fix them.
	@echo "\n\033[36m======== OK: Lints and Formatting ========\033[0m\n"

.PHONY: lint-fix
lint-fix: fmt-toml fmt-ws lint-fix-ws lint-fix-codespell ## Runs all lints and applies fixes where possible.
	@echo "\n\033[36m======== OK: Lints and Formatting Fixes ========\033[0m\n"

.PHONY: rustdocs
rustdocs: ## Runs `cargo docs` to generate the Rust documents in the `target/doc` directory.
	RUSTDOCFLAGS="\
	--show-type-layout \
	--enable-index-page -Z unstable-options \
	-A rustdoc::private-doc-tests \
	-D warnings" \
	cargo doc \
	--workspace \
	--no-deps

.PHONY: test-doc
test-doc: ## Runs doctests on the workspace.
	cargo test --doc --workspace

.PHONY: test
test: ## Runs all tests in the workspace including unit and docs tests.
	make test-unit && \
	make test-doc

.PHONY: pr
pr: lint rustdocs test-doc test-unit ## Runs lints (without fixing), audit, docs, and tests (run this before creating a PR).
	@echo "\n\033[36m======== CHECKS_COMPLETE ========\033[0m\n"
	@test -z "$$(git status --porcelain)" || echo "WARNNG: You have uncommitted changes"
	@echo "All good to create a PR!"


.PHONY: run
run:
	RUST_LOG=info,sp1_start=info,sqlx=info,soketto=error,strata_bridge_db=warn,strata_bridge_tx_graph=warn,strata_btcio=info,strata_bridge_agent=info,hyper_util=error,jsonrpsee=error \
		cargo r \
		--bin strata-bridge \
		--profile "$(PROFILE)" \
		-- \
		--rpc-port 4782 \
		--strata-url ws://localhost:8432 \
		--btc-url http://localhost:18443 \
		--btc-user rpcuser \
		--btc-pass rpcpassword \
		--btc-genesis-height 300 \
		--btc-scan-interval 100 \
		--wallet-prefix bridge \
		--fault-tolerance 100 \
		--duty-interval 120000 \
		--rollup-params-file test-data/rollup_params.json \
		--num-threads 4 \
		--stack-size 512 \
		--xpriv-file .secrets/xprivs.bin \
		--msks-file .secrets/msks.bin 2>&1 | tee run.log.$(TIMESTAMP)

.PHONY: migrate
migrate:
	export DATABASE_URL="sqlite://./operator.db" && \
	rm -f operator.db && \
	touch operator.db && \
	sqlx migrate run


.PHONY: bridge-in
bridge-in:
	RUST_LOG=info \
	cargo r \
		--bin dev-cli \
		-- \
		bridge-in \
		--btc-url http://localhost:18443/wallet/default \
		--btc-user rpcuser \
		--btc-pass rpcpassword \
		--recovery-address bcrt1qsddjnk0u256809tepf8hf6fj90j0qfrgm5t7s8 \
		--strata-address 70997970C51812dc3A010C7d01b50e0d17dc79C8 # from anvil #2

.PHONY: bridge-out
bridge-out:
	RUST_LOG=info \
	cargo r \
		--bin dev-cli \
		-- \
		bridge-out \
		--destination-address-pubkey 94b25feb390fbefadd68f7c1eee7e0c475fea0d1fdde59ba66ab6ca819fce47c \
		--private-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d # from anvil #2
