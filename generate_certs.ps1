# Generate CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout ca.key -out ca.crt -subj "/CN=lib60870-CA"

# Generate server certificate
openssl req -newkey rsa:2048 -sha256 -nodes -keyout server.key -out server.csr -subj "/CN=lib60870-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1825 -sha256

# Generate client certificate
openssl req -newkey rsa:2048 -sha256 -nodes -keyout client.key -out client.csr -subj "/CN=lib60870-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt -days 1825 -sha256

# Clean up
Remove-Item *.csr
Remove-Item *.srl

Write-Host "Certificates generated:"
Write-Host "CA: ca.crt (1.7KB)"
Write-Host "Server: server.crt (1.1KB), server.key"
Write-Host "Client: client.crt (1.1KB), client.key"
