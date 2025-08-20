# Repository Guidelines

## Project Structure & Module Organization
- `crates/`: Core Rust libraries (e.g., `primitives`, `db`, `rpc`, `stake-chain`, `tx-graph`, proof components). Each crate contains its own `src/` and tests.
- `bin/`: Binaries such as `alpen-bridge`, `dev-cli`, `secret-service`, `assert-splitter`.
- `bridge-guest-builder/`: Guest build utilities for proofs.
- `docker/` and `compose.yml`: Local multi-service setup; includes TLS scripts and volumes.
- `migrations/`: SQLx migrations (SQLite by default, `operator.db`).
- `assets/`, `test-data/`: Static assets and sample inputs.
- `Cargo.toml`: Workspace root; `target/`: build outputs.

## Build, Test, and Development Commands
- `just build`: Build the entire workspace (`PROFILE=dev|release`).
- `just test-unit`: Run unit tests with `cargo nextest` (requires `bitcoind`).
- `just test`: Unit + doc tests.
- `just lint` / `just lint-fix`: Check/apply formatting (rustfmt, taplo), clippy, codespell.
- `just pr`: Full pre-PR suite (lint, docs, tests). Recommended before opening a PR.
- `just migrate`: Apply SQLx migrations to `operator.db`.
- Docker: `just docker` (rebuild + start) or `just clean-docker` (clean volumes then rebuild). See `docker/README.md`.

## Coding Style & Naming Conventions
- Indentation: spaces (4); TOML/YAML: 2 (enforced by `.editorconfig`).
- Rust formatting via `rustfmt` (`rustfmt.toml`), max logical width ~100, grouped imports.
- Linting: clippy warnings denied; workspace lints deny `missing_docs`, `unreachable_pub`, `unused_*`. Add doc comments for public items.
- Naming: crates `kebab-case`; modules/functions/vars `snake_case`; types/traits `CamelCase`; constants `SCREAMING_SNAKE_CASE`.
- TOML formatted with `taplo`.

## Testing Guidelines
- Framework: Rust tests with `nextest`; doc tests via `cargo test --doc`.
- Commands: `just test-unit`, `just test`, coverage with `just cov-unit` and `just cov-report-html`.
- Location: intra-crate `tests/` or `mod tests` blocks. Prefer descriptive names like `foo_tests.rs`.

## Commit & Pull Request Guidelines
- Commits: Conventional style (e.g., `feat(scope): ...`, `fix!: ...`, `docs: ...`, `perf: ...`, `chore(deps): ...`).
- PRs: Use the template, provide a clear description, link issues (`closes #123`), and check the boxes. Run `just pr` locally; include migration notes or config changes where relevant.

## Security & Configuration Tips
- Copy `.sample_env` as needed and configure SP1 credentials; guard secrets in logs.
- TLS for local Secret Service: `just gen-s2-tls` (or `gen-s2-tls-{1,2,3}`).
- Database: default SQLite (`DATABASE_URL=sqlite://./operator.db`).
