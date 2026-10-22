E2EE chat server: the handshake (prekeys, X3DH initial messages) and mailbox services over gRPC, kept in memory.

```sh
An E2EE chat server.

Usage: e2ee_chat_server [OPTIONS] <LISTENING_ON>

Arguments:
  <LISTENING_ON>  The address to listen on, e.g. 0.0.0.0:443

Options:
  -c, --cert <CERT>  The path to cert(pem)
  -k, --key <KEY>    The path to key(pem)
  -h, --help         Print help
  -V, --version      Print version
```

```sh
# copy cert
acme.sh --install-cert -d example.com --fullchain-file tls/server.crt --key-file tls/server.key
```
