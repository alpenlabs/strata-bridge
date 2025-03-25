# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 ghcr.io/succinctlabs/sp1:latest AS builder

WORKDIR /app

# Set environment variables for optimized release builds
ENV CARGO_INCREMENTAL=0
ENV CARGO_TERM_COLOR=always
ENV TARGET=x86_64-unknown-linux-musl

# Install system dependencies
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y \
    pkg-config \
    build-essential protobuf-compiler git

COPY rust-toolchain.toml rust-toolchain.toml
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo

# check sp1 is setup properly
RUN cargo +succinct --version

COPY . .

# Download dependencies in release mode
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo fetch

# Build deps
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo b -r

# Build bridge node
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo b -r -p alpen-bridge

RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cp /app/target/release/alpen-bridge /app/alpen-bridge

FROM --platform=linux/amd64 ubuntu:24.04 AS runtime
WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binaries from the builder stage
COPY --from=builder /app/alpen-bridge /usr/local/bin/alpen-bridge
COPY docker/alpen-bridge/entrypoint.sh /usr/local/bin/entrypoint.sh
# RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5678

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
