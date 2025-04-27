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
