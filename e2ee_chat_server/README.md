Start gRPC Message and X3DH server.

```rust
// "UPSTREAM" of Pingora reverse proxy
let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| "cert/cert.pem".to_string());
let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| "cert/key.pem".to_string());
```
