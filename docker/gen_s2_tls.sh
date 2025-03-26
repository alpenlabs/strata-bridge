# run from the root of the repo!!!

S2_TLS_DIR=docker/vol/secret-service/tls
BRIDGE_TLS_DIR=docker/vol/alpen-bridge/tls

rm -rf $S2_TLS_DIR $BRIDGE_TLS_DIR
mkdir -p $S2_TLS_DIR $BRIDGE_TLS_DIR

# Generate Bridge Node CA
openssl genpkey -algorithm RSA -out bridge_node_ca.key
openssl req -x509 -new -nodes -key bridge_node_ca.key -sha256 -days 365 -out bridge_node_ca.crt -subj "/CN=Bridge Node CA"

# Generate Secret Service CA
openssl genpkey -algorithm RSA -out secret_service_ca.key
openssl req -x509 -new -nodes -key secret_service_ca.key -sha256 -days 365 -out secret_service_ca.crt -subj "/CN=Secret Service CA"

# Generate key pair for bridge operator
openssl genpkey -algorithm RSA -out bridge_node.key
openssl req -new -key bridge_node.key -out bridge_node.csr -subj "/CN=Bridge Operator"
openssl x509 -req -in bridge_node.csr -CA bridge_node_ca.crt -CAkey bridge_node_ca.key -CAcreateserial -out bridge_node.crt -days 365 -sha256

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
EOF

# Generate key pair for secret-service with domain name support
openssl genpkey -algorithm RSA -out secret_service.key
openssl req -new -key secret_service.key -out secret_service.csr -config secret_service.cnf
openssl x509 -req -in secret_service.csr -CA secret_service_ca.crt -CAkey secret_service_ca.key -CAcreateserial -out secret_service.crt -days 365 -sha256 -extfile secret_service.cnf -extensions v3_req

# Convert to DER format
openssl x509 -outform der -in bridge_node.crt -out $BRIDGE_TLS_DIR/cert.der
openssl rsa -outform der -in bridge_node.key -out $BRIDGE_TLS_DIR/key.der
openssl x509 -outform der -in secret_service.crt -out $S2_TLS_DIR/cert.der
openssl rsa -outform der -in secret_service.key -out $S2_TLS_DIR/key.der
openssl x509 -outform der -in bridge_node_ca.crt -out $S2_TLS_DIR/bridge.ca.der
openssl x509 -outform der -in secret_service_ca.crt -out $BRIDGE_TLS_DIR/s2.ca.der

# Verify certificates
openssl verify -CAfile bridge_node_ca.crt bridge_node.crt
openssl verify -CAfile secret_service_ca.crt secret_service.crt

# Display the certificate to confirm SAN extension
echo "Verifying SAN extension for secret-service certificate:"
openssl x509 -in secret_service.crt -text -noout | grep -A1 "Subject Alternative Name"

# Clean up
rm *.crt *.key *.csr *.srl *.cnf
