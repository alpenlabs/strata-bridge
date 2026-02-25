#!/usr/bin/env bash
# run via `just gen-s2-tls` not directly!
#
# Generates mTLS materials for one bridge operator:
# - bridge_node/tls/{key.pem,cert.pem,s2.ca.pem}
# - secret_service/tls/{key.pem,cert.pem,bridge.ca.pem}
# The trust model is intentionally cross-signed so each side validates the other.

set -euo pipefail

BRIDGE_BASE_DIR="${1:-docker/vol/alpen-bridge}"
S2_BASE_DIR="${2:-docker/vol/secret-service}"
IP="${3:-172.28.1.6}"

# Prefer `openssl` from PATH. On macOS, forcing `/usr/bin/openssl` (LibreSSL)
# can emit v1 client certs for this flow, which rustls rejects.
if [ -z "${OPENSSL_BIN:-}" ]; then
  OPENSSL_BIN="$(command -v openssl || true)"
fi
if [ -z "${OPENSSL_BIN:-}" ] && [ -x /usr/bin/openssl ]; then
  OPENSSL_BIN="/usr/bin/openssl"
fi
if [ -z "${OPENSSL_BIN:-}" ]; then
  echo "openssl binary not found" >&2
  exit 1
fi

# OpenSSL CLI may require a config file even for simple `req`/`x509` commands.
# Some CI installs (e.g. `make install_sw`) do not include `openssl.cnf`,
# so fall back to a known system config when needed.
if [ -z "${OPENSSL_CONF:-}" ]; then
  openssl_prefix="$(cd "$(dirname "$OPENSSL_BIN")/.." && pwd)"
  if [ -f "${openssl_prefix}/openssl.cnf" ]; then
    export OPENSSL_CONF="${openssl_prefix}/openssl.cnf"
  elif [ -f "${openssl_prefix}/etc/openssl.cnf" ]; then
    export OPENSSL_CONF="${openssl_prefix}/etc/openssl.cnf"
  elif [ -f "${openssl_prefix}/etc/openssl@3/openssl.cnf" ]; then
    export OPENSSL_CONF="${openssl_prefix}/etc/openssl@3/openssl.cnf"
  elif [ -f /usr/local/etc/openssl@3/openssl.cnf ]; then
    export OPENSSL_CONF=/usr/local/etc/openssl@3/openssl.cnf
  elif [ -f /opt/homebrew/etc/openssl@3/openssl.cnf ]; then
    export OPENSSL_CONF=/opt/homebrew/etc/openssl@3/openssl.cnf
  elif [ -f /etc/ssl/openssl.cnf ]; then
    export OPENSSL_CONF=/etc/ssl/openssl.cnf
  fi
fi

S2_TLS_DIR="${S2_BASE_DIR}/tls"
BRIDGE_TLS_DIR="${BRIDGE_BASE_DIR}/tls"

openssl() {
  # On Linux CI we rely on LD_LIBRARY_PATH to load cached OpenSSL shared libs.
  # On macOS, clearing LD_LIBRARY_PATH avoids accidental loader conflicts.
  if [ "$(uname -s)" = "Darwin" ]; then
    env -u LD_LIBRARY_PATH "$OPENSSL_BIN" "$@"
  else
    "$OPENSSL_BIN" "$@"
  fi
}

# Recreate TLS output dirs from scratch for deterministic test credentials.
rm -rf "$S2_TLS_DIR" "$BRIDGE_TLS_DIR"
mkdir -p "$S2_TLS_DIR" "$BRIDGE_TLS_DIR"

# Generate Bridge Node CA
openssl genpkey -algorithm RSA -out bridge_node_ca.key
openssl req -x509 -new -nodes -key bridge_node_ca.key -sha256 -days 365 -out "$S2_TLS_DIR/bridge.ca.pem" -subj "/CN=Bridge Node CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# Generate Secret Service CA
openssl genpkey -algorithm RSA -out secret_service_ca.key
openssl req -x509 -new -nodes -key secret_service_ca.key -sha256 -days 365 -out "$BRIDGE_TLS_DIR/s2.ca.pem" -subj "/CN=Secret Service CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# Generate key pair for bridge operator
# Bridge cert is used for client-auth; force v3 extensions explicitly so
# rustls does not reject a v1 certificate when OpenSSL defaults differ.
cat > bridge_node.cnf <<EOF
[v3_req]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl genpkey -algorithm RSA -out "$BRIDGE_TLS_DIR/key.pem"
openssl req -new -key "$BRIDGE_TLS_DIR/key.pem" -out bridge_node.csr -subj "/CN=Bridge Operator"
openssl x509 -req -in bridge_node.csr -CA "$S2_TLS_DIR/bridge.ca.pem" -CAkey bridge_node_ca.key -CAcreateserial \
  -out "$BRIDGE_TLS_DIR/cert.pem" -days 365 -sha256 -extfile bridge_node.cnf -extensions v3_req

# Create config file for secret-service with SAN
# Keep SAN explicit so local connection by IP is always valid in tests.
cat > secret_service.cnf <<EOF
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
openssl genpkey -algorithm RSA -out "$S2_TLS_DIR/key.pem"
openssl req -new -key "$S2_TLS_DIR/key.pem" -out secret_service.csr -config secret_service.cnf
openssl x509 -req -in secret_service.csr -CA "$BRIDGE_TLS_DIR/s2.ca.pem" -CAkey secret_service_ca.key -CAcreateserial -out "$S2_TLS_DIR/cert.pem" -days 365 -sha256 -extfile secret_service.cnf -extensions v3_req

# Verify certificates
# Bridge cert must chain to bridge CA visible by secret-service.
openssl verify -CAfile "$S2_TLS_DIR/bridge.ca.pem" "$BRIDGE_TLS_DIR/cert.pem"
# Secret-service cert must chain to s2 CA visible by bridge.
openssl verify -CAfile "$BRIDGE_TLS_DIR/s2.ca.pem" "$S2_TLS_DIR/cert.pem"

# Display the certificate to confirm SAN extension
echo "Verifying SAN extension for secret-service certificate:"
openssl x509 -in "$S2_TLS_DIR/cert.pem" -text -noout | grep -A1 "Subject Alternative Name"

# Clean up
# Remove only temporary generation artifacts; keep final TLS outputs above.
rm -f *.csr "$BRIDGE_TLS_DIR"/*.srl "$S2_TLS_DIR"/*.srl *.cnf *ca.key
