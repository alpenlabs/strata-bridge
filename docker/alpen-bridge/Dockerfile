# warning: run from repo root, NOT inside this dir
FROM --platform=linux/amd64 bridge-base:latest AS builder

# It's already in the builder but this is so docker knows when to rebuild this image
COPY bin/alpen-bridge bin/alpen-bridge

# Build bridge node
RUN cargo b -r -p alpen-bridge

RUN cp /app/target/release/alpen-bridge /app/alpen-bridge

FROM --platform=linux/amd64 bridge-rt:latest AS runtime

# Copy the built binaries from the builder stage
COPY --from=builder /app/alpen-bridge /usr/local/bin/alpen-bridge
COPY --from=builder /app/migrations /app/migrations
COPY docker/alpen-bridge/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 5678
EXPOSE 3000

ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
