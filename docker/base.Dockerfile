FROM --platform=linux/amd64 ghcr.io/succinctlabs/sp1:latest AS builder

WORKDIR /app

# Set environment variables for optimized release builds
ENV CARGO_INCREMENTAL=0
ENV CARGO_TERM_COLOR=always

# Install system dependencies
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y \
    pkg-config build-essential protobuf-compiler git

COPY rust-toolchain.toml rust-toolchain.toml
RUN cargo

# check sp1 is setup properly
RUN cargo +succinct --version

COPY . .

# Download external deps
RUN cargo fetch

# Build deps and everything except binaries
RUN cargo b -r --workspace $(ls bin | grep -v / | xargs -I{} echo "--exclude {}")
