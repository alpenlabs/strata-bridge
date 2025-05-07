# run via `make gen-s2-tls` not directly!

BRIDGE_BASE_DIR=${1:-docker/vol/alpen-bridge}
S2_BASE_DIR=${2:-docker/vol/secret-service}

S2_TLS_DIR=${S2_BASE_DIR}/tls
BRIDGE_TLS_DIR=${BRIDGE_BASE_DIR}/tls
IP=172.28.1.6

rm -rf $S2_TLS_DIR $BRIDGE_TLS_DIR
mkdir -p $S2_TLS_DIR $BRIDGE_TLS_DIR

# Generate Bridge Node CA
openssl genpkey -algorithm RSA -out bridge_node_ca.key
openssl req -x509 -new -nodes -key bridge_node_ca.key -sha256 -days 365 -out $S2_TLS_DIR/bridge.ca.pem -subj "/CN=Bridge Node CA"

# Generate Secret Service CA
openssl genpkey -algorithm RSA -out secret_service_ca.key
openssl req -x509 -new -nodes -key secret_service_ca.key -sha256 -days 365 -out $BRIDGE_TLS_DIR/s2.ca.pem -subj "/CN=Secret Service CA"

# Generate key pair for bridge operator
openssl genpkey -algorithm RSA -out $BRIDGE_TLS_DIR/key.pem
openssl req -new -key $BRIDGE_TLS_DIR/key.pem -out bridge_node.csr -subj "/CN=Bridge Operator"
openssl x509 -req -in bridge_node.csr -CA $S2_TLS_DIR/bridge.ca.pem -CAkey bridge_node_ca.key -CAcreateserial -out $BRIDGE_TLS_DIR/cert.pem -days 365 -sha256

# Create config file for secret-service with SAN
cat > secret_service.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = Secret Service

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = secret-service
IP.1 = $IP
EOF

# Generate key pair for secret-service with domain name support
openssl genpkey -algorithm RSA -out $S2_TLS_DIR/key.pem
openssl req -new -key $S2_TLS_DIR/key.pem -out secret_service.csr -config secret_service.cnf
openssl x509 -req -in secret_service.csr -CA $BRIDGE_TLS_DIR/s2.ca.pem -CAkey secret_service_ca.key -CAcreateserial -out $S2_TLS_DIR/cert.pem -days 365 -sha256 -extfile secret_service.cnf -extensions v3_req

# Verify certificates
openssl verify -CAfile $S2_TLS_DIR/bridge.ca.pem $BRIDGE_TLS_DIR/cert.pem
openssl verify -CAfile $BRIDGE_TLS_DIR/s2.ca.pem $S2_TLS_DIR/cert.pem

# Display the certificate to confirm SAN extension
echo "Verifying SAN extension for secret-service certificate:"
openssl x509 -in $S2_TLS_DIR/cert.pem -text -noout | grep -A1 "Subject Alternative Name"

# Clean up
rm *.csr $BRIDGE_TLS_DIR/*.srl $S2_TLS_DIR/*.srl *.cnf *ca.key
