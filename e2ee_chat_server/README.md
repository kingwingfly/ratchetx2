Start gRPC Message and X3DH server.

```sh
An E2EE chat server.

Usage: e2ee_chat_server [OPTIONS] <LISTENING_ON>

Arguments:
  <LISTENING_ON>  The E2EE chat server address

Options:
  -c, --cert <CERT>  The path to cert(pem)
  -k, --key <KEY>    The path to key(pem)
  -h, --help         Print help
  -V, --version      Print version
```

```sh
# copy cert
acme.sh --install-cert -d chat.louisfly.icu --fullchain-file tls/server.crt --key-file tls/server.key
```
