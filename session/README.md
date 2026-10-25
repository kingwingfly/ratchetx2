The E2EE chat's client flow: X3DH over the [handshake](../protocol) service, then a double ratchet ([party](../party)) over the mailbox service.

- [`Client`] is an identity on a handshake server. It publishes prekeys, starts sessions ([`Client::initiate`]) and accepts them ([`Client::take_initial_messages`], [`Client::accept`]).
- [`Session`] is a conversation with one peer. It encrypts, pushes and fetches messages.

Both take any client of the [protocol](../protocol) traits, so the same flow runs over Connect, in-process, or a transport of your own. Alice's initial message carries the session's first message, so Bob can write back as soon as he accepts it.

Anyone can send an initial message claiming to be anyone, but only the real sender can have encrypted its first message, as X3DH's keys take the sender's identity key: [`Client::accept`] fails unless it decrypts, and then uses up nothing, so a forged initial message changes nothing. Nothing is signed, so neither peer can prove to others that they talked.

When a known peer starts a new session, or this client does, the new one becomes the session, and [`Session::keep`] keeps the old one behind it: messages sent on the old one still decrypt, and if the new one gets no answer, e.g. as its initial message was lost, the old one takes over again. Two peers who start a session at once each keep both, so no message is lost.

Files too large for a message go as attachments ([`attachment`]): [`Client::start_upload`] starts one under a new key, its chunks are encrypted and uploaded, and a message carries the attachment's ID and key, so that its recipients download and decrypt the chunks.

To check that nobody swapped an identity key between two peers, e.g. a server in the middle, they compare their [`safety_number`] out of band: 60 digits, computed as Signal's are, the same on both sides only if each has the other's real key.

To keep them between runs, save their states ([`Client::state`], [`Session::state`]) and restore them with [`Client::restore`] and [`Session::restore`]. The states serialize with serde or rkyv, or convert to and from protobuf messages, as the features below enable. They hold private keys, so keep them secret, e.g. encrypted.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **serde**, **rkyv**: serialize [`ClientState`] and [`SessionState`].
- **prost**: the states as protobuf messages too, defined in `proto/session.proto` (package `session.v1`), in the `proto` module; they are zeroized on drop.
- **connect**: Connect clients over any HTTP client, in `protocol::connect`.

On `wasm32-unknown-unknown`, enable getrandom's `wasm_js` feature in the final application.

# Example

Over Connect, with the `connect` feature:

```rust,no_run
use session::Client;
use session::protocol::connect::{ConnectClient, Post};

/// Posts the calls with the HTTP client of your choice, e.g. reqwest, or `fetch` in a browser.
#[derive(Clone)]
struct Http;

impl Post for Http {
    async fn post(&self, path: &str, body: Vec<u8>) -> session::protocol::Result<(u16, Vec<u8>)> {
        // POST `body` to the server's address and `path`, e.g.
        // https://chat.example.com/mailbox.v1.MailboxService/Push, with the headers
        // `Content-Type: application/proto` and `Connect-Protocol-Version: 1`, and return the
        // response's status and body.
#       unimplemented!()
    }
}

# async fn run() -> session::Result<()> {
let server = ConnectClient::new(Http);
let mut alice = Client::new(server.clone());
let mut bob = Client::new(server.clone());

// Bob publishes his prekeys; Alice starts a session, saying hi, and sends a message.
bob.publish_keys(10).await?;
let mut alice_session = alice
    .initiate(&bob.identity_key(), b"Hi Bob", server.clone())
    .await?;
alice_session.send(b"How are you?").await?;

// Bob accepts it, expecting it from Alice, as its first message shows; then they can talk.
let initial_messages = bob.take_initial_messages().await?;
let (mut bob_session, hi) = bob.accept(&alice.identity_key(), &initial_messages[0], server)?;
println!("{}", String::from_utf8_lossy(&hi));
for content in bob_session.receive().await? {
    println!("{}", String::from_utf8_lossy(&content?));
}
bob_session.send(b"Hi Alice").await?;
# Ok(())
# }
```
