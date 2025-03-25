# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 rust:latest AS builder

WORKDIR /app

# Set environment variables for optimized release builds
ENV CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=always
# TARGET=x86_64-unknown-linux-musl

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    pkg-config \
    build-essential protobuf-compiler

COPY rust-toolchain.toml rust-toolchain.toml

# SP1
RUN curl -L https://sp1up.succinct.xyz | bash && ~/.sp1/bin/sp1up --c-toolchain
ENV PATH="/root/.sp1/bin:$PATH"
# check sp1 is setup properly
RUN cargo prove --version
# RUN RUSTUP_TOOLCHAIN=succinct cargo --version

# Cache toolchain
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo


COPY . .

# Build dependencies in release mode
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo fetch

# Build bridge node
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cargo build --release -p alpen-bridge


RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=private,target=/app/target \
    cp /app/target/release/alpen-bridge /app/alpen-bridge

FROM ubuntu:24.04 AS runtime
WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binaries from the builder stage
COPY --from=builder /app/alpen-bridge /usr/local/bin/alpen-bridge

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/alpen-bridge", "/app/config.toml"]
