# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

# It's already in the builder but this is so docker knows when to rebuild this image
COPY bin/secret-service bin/secret-service

RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo b -r -p secret-service --features memory_profiling

RUN --mount=type=cache,target=/app/target cp /app/target/release/secret-service /app/secret-service

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

# Copy the built binaries from the builder stage
COPY --from=builder /app/secret-service /usr/local/bin/secret-service

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/secret-service", "/app/config.toml"]
