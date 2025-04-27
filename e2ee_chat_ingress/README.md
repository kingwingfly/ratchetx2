**(Deprecated: Pingora cannot work with tonic gRPC, use tonic tls instead)**

A reverse proxy with Pingora for [e2ee-chat-server](https://crates.io/crates/e2ee_chat_server).

# ENV VARS

```rust
let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| "tls/cert.pem".to_string());
let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| "tls/key.pem".to_string());
let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:443".to_string());
```
