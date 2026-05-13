# ghcr.io/succinctlabs/sp1:v6.1.0
# get image digest from: `docker buildx imagetools inspect ghcr.io/succinctlabs/sp1:v6.1.0 2>&1 | head -20`
FROM --platform=linux/amd64 ghcr.io/succinctlabs/sp1@sha256:484abccef8b457bfce8159f53364e93e0c78be6e5187a17e04c09856a7861576 AS builder

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

# ELF will be built separately so no need to build it here.
ENV SP1_SKIP_PROGRAM_BUILD=true

# Build deps and everything except binaries
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo b -r --workspace --exclude memory_pprof $(ls bin | grep -v / | xargs -I{} echo "--exclude {}")
