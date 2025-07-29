#!/bin/bash

set -e  # Exit immediately on error

N=3  # Number of iterations (modifiable)

BASE_DIR="certs"

mkdir -p "$BASE_DIR"

for i in $(seq 1 $N); do
    CERT_DIR="$BASE_DIR/$i"
    echo "Generating certificates for iteration $i in $CERT_DIR..."

    mkdir -p "$CERT_DIR" && cd "$CERT_DIR"

    # Generate Bridge Node CA
    openssl genpkey -algorithm RSA -out bridge_node_ca.key
    openssl req -x509 -new -nodes -key bridge_node_ca.key -sha256 -days 365 -out bridge_node_ca.crt -subj "/CN=Bridge Node CA $i"

    # Generate Secret Service CA
    openssl genpkey -algorithm RSA -out secret_service_ca.key
    openssl req -x509 -new -nodes -key secret_service_ca.key -sha256 -days 365 -out secret_service_ca.crt -subj "/CN=Secret Service CA $i"

    # Generate key pair for bridge operator
    openssl genpkey -algorithm RSA -out bridge_node.key
    openssl req -new -key bridge_node.key -out bridge_node.csr -subj "/CN=Bridge Operator $i"
    openssl x509 -req -in bridge_node.csr -CA bridge_node_ca.crt -CAkey bridge_node_ca.key -CAcreateserial -out bridge_node.crt -days 365 -sha256

    # Generate key pair for secret-service
    openssl genpkey -algorithm RSA -out secret_service.key
    openssl req -new -key secret_service.key -out secret_service.csr -subj "/CN=Secret Service $i"
    openssl x509 -req -in secret_service.csr -CA secret_service_ca.crt -CAkey secret_service_ca.key -CAcreateserial -out secret_service.crt -days 365 -sha256

    # Verify certificates
    openssl verify -CAfile bridge_node_ca.crt bridge_node.crt
    openssl verify -CAfile secret_service_ca.crt secret_service.crt

    echo "Iteration $i certificates generated successfully."

    # Return to base directory
    cd ..
done

echo "All iterations completed. Certificates are stored in $BASE_DIR/{1..$N}/"
