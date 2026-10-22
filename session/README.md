The E2EE chat's client flow: X3DH over the [handshake](../protocol) service, then a double ratchet ([party](../party)) over the mailbox service.

- [`Client`] is an identity on a handshake server. It publishes prekeys, starts sessions ([`Client::initiate`]) and accepts them ([`Client::take_introductions`], [`Client::accept`]).
- [`Session`] is a conversation with one peer. It encrypts, pushes and fetches messages.

Both take any client of the [protocol](../protocol) traits, so the same flow runs over gRPC, in-process, or a transport of your own. Bob can send only after he has received Alice's first message ([`ErrorKind::NoSendingChain`]).

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **grpc**: gRPC clients, in `protocol::grpc`.

On `wasm32-unknown-unknown`, enable getrandom's `wasm_js` feature in the final application.

# Example

```rust,no_run
use session::Client;
use session::protocol::grpc::{GrpcHandshake, GrpcMailbox, connect};

# async fn run() -> session::Result<()> {
let channel = connect("https://chat.example.com:3000", None).await?;
let mut alice = Client::new(GrpcHandshake::new(channel.clone()));
let mut bob = Client::new(GrpcHandshake::new(channel.clone()));

// Bob publishes his prekeys; Alice starts a session and sends a message.
bob.publish_keys(10).await?;
let mut alice_session = alice
    .initiate(&bob.identity_key(), GrpcMailbox::new(channel.clone()))
    .await?;
alice_session.send(b"Hi Bob").await?;

// Bob accepts it, expecting it from Alice, then they can talk.
let introductions = bob.take_introductions().await?;
let mut bob_session = bob.accept(&alice.identity_key(), &introductions[0], GrpcMailbox::new(channel))?;
for content in bob_session.receive().await? {
    println!("{}", String::from_utf8_lossy(&content?));
}
bob_session.send(b"Hi Alice").await?;
# Ok(())
# }
```
