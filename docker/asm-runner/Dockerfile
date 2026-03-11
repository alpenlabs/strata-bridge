# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

# It's already in the builder but this is so docker knows when to rebuild this image
COPY bin/asm-runner bin/asm-runner

RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo b -r -p strata-asm-runner

RUN --mount=type=cache,target=/app/target cp /app/target/release/strata-asm-runner /app/strata-asm-runner

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/strata-asm-runner /usr/local/bin/strata-asm-runner

ENTRYPOINT ["/usr/local/bin/strata-asm-runner", "--config", "/app/config.toml", "--params", "/app/asm-params.json"]
