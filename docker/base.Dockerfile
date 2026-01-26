FROM --platform=linux/amd64 ghcr.io/succinctlabs/sp1:nightly AS builder

WORKDIR /app

# Set environment variables for optimized release builds
ENV CARGO_INCREMENTAL=0
ENV CARGO_TERM_COLOR=always

# Install system dependencies
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y \
    pkg-config build-essential protobuf-compiler git curl

# Install FoundationDB client library (required for building)
ARG FDB_VERSION=7.3.43
RUN curl -fsSLO --proto "=https" --tlsv1.2 \
    "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb" && \
    dpkg -i "foundationdb-clients_${FDB_VERSION}-1_amd64.deb" && \
    rm -f "foundationdb-clients_${FDB_VERSION}-1_amd64.deb"

COPY rust-toolchain.toml rust-toolchain.toml
RUN rustup show
RUN cargo --version

# check sp1 is setup properly
RUN cargo +succinct --version

COPY . .

# Download external deps
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo fetch

# Build deps and everything except binaries
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo b -r --workspace --exclude memory_pprof $(ls bin | grep -v / | xargs -I{} echo "--exclude {}")
