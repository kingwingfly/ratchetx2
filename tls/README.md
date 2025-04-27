Self-signed tls keys for test.

```sh
# Gen CA private key
openssl ecparam -name prime256v1 -genkey -out ca.key
# Gen Certificate Sign Request (CSR) (`127.0.0.1` as Common Name)
openssl req -new -sha256 -key ca.key -out ca.csr
# Gen CA certificate
openssl x509 -req -sha256 -days 365 -in ca.csr -signkey ca.key -out ca.crt

# Gen server private key
openssl ecparam -name prime256v1 -genkey -out server.key
# Gen Certificate Sign Request (CSR) (`127.0.0.1` as Common Name)
openssl req -new -sha256 -key server.key -out server.csr
# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
```

```sh
# 1. Gen CA private key
openssl ecparam -name prime256v1 -genkey -out ca.key

# 2. Gen CA certificate
openssl req -x509 -new -sha256 -nodes -key ca.key -days 365 -out ca.crt -subj "/CN=Test CA"

# 3. Gen server private key
openssl ecparam -name prime256v1 -genkey -out server.key

# 4. SAN CSR Conf
cat > server.csr.conf <<EOF
[ req ]
default_bits = 256
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = 127.0.0.1

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 5. Gen CSR（with SAN）
openssl req -new -sha256 -key server.key -out server.csr -config server.csr.conf

# 6. Create certificate extension configuration file
cat > server.crt.conf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 7. Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
-out server.crt -days 365 -sha256 -extfile server.crt.conf
```
