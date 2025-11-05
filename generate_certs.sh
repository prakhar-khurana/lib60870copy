#!/bin/bash
# Certificate Generation Script for IEC 60870-5-104 with TLS/IEC 62351-5
# Generates CA, server, and client certificates for secure communication

set -e

CERT_DIR="certs"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   IEC 60870-5-104 Certificate Generator                   ║"
echo "║   Creates CA, Server, and Client certificates             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Create certificate directory if it doesn't exist
if [ ! -d "$CERT_DIR" ]; then
    echo "Creating certificate directory: $CERT_DIR"
    mkdir -p "$CERT_DIR"
fi

cd "$CERT_DIR"

echo "Step 1: Generating Certificate Authority (CA)..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/CN=lib60870-CA/O=IEC60870/C=US"

echo "✓ CA certificate generated"
echo ""

echo "Step 2: Generating Server Certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=lib60870-server/O=IEC60870/C=US"

openssl x509 -req -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 1825 -sha256

echo "✓ Server certificate generated"
echo ""

echo "Step 3: Generating Client Certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout client.key -out client.csr \
    -subj "/CN=lib60870-client/O=IEC60870/C=US"

openssl x509 -req -in client.csr \
    -CA ca.crt -CAkey ca.key \
    -out client.crt -days 1825 -sha256

echo "✓ Client certificate generated"
echo ""

echo "Step 4: Cleaning up temporary files..."
rm -f *.csr *.srl

echo "✓ Cleanup complete"
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   CERTIFICATES GENERATED SUCCESSFULLY                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Display certificate information
echo "Certificate Details:"
echo "-------------------"
echo "Directory: $(pwd)"
echo ""

if [ -f "ca.crt" ]; then
    CA_SIZE=$(du -h ca.crt | cut -f1)
    echo "CA Certificate:     ca.crt ($CA_SIZE)"
    echo "CA Private Key:     ca.key"
fi

if [ -f "server.crt" ]; then
    SERVER_SIZE=$(du -h server.crt | cut -f1)
    echo "Server Certificate: server.crt ($SERVER_SIZE)"
    echo "Server Private Key: server.key"
fi

if [ -f "client.crt" ]; then
    CLIENT_SIZE=$(du -h client.crt | cut -f1)
    echo "Client Certificate: client.crt ($CLIENT_SIZE)"
    echo "Client Private Key: client.key"
fi

echo ""
echo "Verify certificates with:"
echo "  openssl x509 -in ca.crt -text -noout"
echo "  openssl x509 -in server.crt -text -noout"
echo "  openssl x509 -in client.crt -text -noout"
echo ""

# Set appropriate permissions
chmod 600 *.key
chmod 644 *.crt

echo "✓ Permissions set (keys: 600, certs: 644)"
echo ""
echo "Certificates are ready to use!"
