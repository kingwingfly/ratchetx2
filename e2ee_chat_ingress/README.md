A reverse proxy with Pingora.

# ENV VARS

```rust
let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| "tls/cert.pem".to_string());
let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| "tls/key.pem".to_string());
let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:443".to_string());
```
