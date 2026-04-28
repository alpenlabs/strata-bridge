# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

# Copy the workspace Cargo.toml so the grep-extracted tag is the canonical source of truth.
COPY Cargo.toml /tmp/Cargo.toml

RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    ASM_REV=$(grep 'strata-asm-worker.*rev' /tmp/Cargo.toml | sed 's/.*rev = "\([^"]*\)".*/\1/') && \
    if [ -z "$ASM_REV" ]; then \
        echo "ERROR: failed to extract asm rev from Cargo.toml" >&2; exit 1; \
    fi && \
    cargo install --git https://github.com/alpenlabs/asm --rev "$ASM_REV" --root /app strata-asm-runner

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

WORKDIR /app

RUN apt-get update && \
    apt-get install -y python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /app/bin/strata-asm-runner /usr/local/bin/strata-asm-runner
COPY functional-tests/factory/common/asm_params.py /usr/local/bin/asm_params.py
COPY functional-tests/constants.py /usr/local/bin/constants.py
COPY docker/asm-runner/gen_asm_params.py /usr/local/bin/gen_asm_params.py
COPY docker/asm-runner/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
