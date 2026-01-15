FROM --platform=linux/amd64 ubuntu:24.04
WORKDIR /app

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y curl

# Install FoundationDB client library (required at runtime)
ARG FDB_VERSION=7.3.43
RUN curl -fsSLO --proto "=https" --tlsv1.2 \
    "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb" && \
    dpkg -i "foundationdb-clients_${FDB_VERSION}-1_amd64.deb" && \
    rm -f "foundationdb-clients_${FDB_VERSION}-1_amd64.deb"

RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*
