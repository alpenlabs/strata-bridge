# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

# It's already in the builder but this is so docker knows when to rebuild this image
COPY bin/alpen-bridge bin/alpen-bridge

# Build bridge node
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo b -r -p alpen-bridge

RUN --mount=type=cache,target=/app/target cp /app/target/release/alpen-bridge /app/alpen-bridge

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

# Copy the built binaries from the builder stage
COPY --from=builder /app/alpen-bridge /usr/local/bin/alpen-bridge
COPY docker/alpen-bridge/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 5678

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
