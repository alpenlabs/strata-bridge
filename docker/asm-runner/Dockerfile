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

RUN apt-get update && \
    apt-get install -y python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /app/strata-asm-runner /usr/local/bin/strata-asm-runner
COPY functional-tests/factory/common/asm_params.py /usr/local/bin/asm_params.py
COPY functional-tests/constants.py /usr/local/bin/constants.py
COPY docker/asm-runner/gen_asm_params.py /usr/local/bin/gen_asm_params.py
COPY docker/asm-runner/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
