# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

ARG ASM_FEATURES=""

# Copy the workspace Cargo.toml so the grep-extracted tag is the canonical source of truth.
COPY Cargo.toml /tmp/Cargo.toml

RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    ASM_DEP=$(grep -E '^[[:space:]]*strata-asm-worker[[:space:]]*=' /tmp/Cargo.toml) && \
    ASM_REF_TYPE=$(printf '%s\n' "$ASM_DEP" | sed -n 's/.*tag[[:space:]]*=[[:space:]]*"[^"]*".*/tag/p; s/.*rev[[:space:]]*=[[:space:]]*"[^"]*".*/rev/p') && \
    ASM_REF=$(printf '%s\n' "$ASM_DEP" | sed -n 's/.*tag[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p; s/.*rev[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p') && \
    if [ -z "$ASM_REF_TYPE" ] || [ -z "$ASM_REF" ]; then \
        echo "ERROR: failed to extract asm git ref from Cargo.toml" >&2; exit 1; \
    fi && \
    cargo install --locked --git https://github.com/alpenlabs/asm "--$ASM_REF_TYPE" "$ASM_REF" --root /app strata-asm-runner ${ASM_FEATURES}

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/bin/strata-asm-runner /usr/local/bin/strata-asm-runner
COPY docker/asm-runner/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
