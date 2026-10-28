The E2EE chat's client flow: X3DH over the [handshake](../protocol) service, then a double ratchet ([party](../party)) over the mailbox service.

- [`Client`] is an identity on a handshake server. It publishes prekeys, starts sessions ([`Client::initiate`]) and accepts them ([`Client::take_initial_messages`], [`Client::accept`]).
- [`Session`] is a conversation with one peer. It encrypts, pushes and fetches messages.

Both take any client of the [protocol](../protocol) traits, so the same flow runs over Connect, in-process, or a transport of your own. A message leaves the server once its recipient has it: [`Session::encrypt`] gives, with the message, SHA-256 of its delivery token, HMAC-SHA256 of its encrypted header under a key from X3DH's shared secret of the session it is encrypted on, which only the two peers can compute; [`Session::push`] gives the server that hash, and the recipient's next [`Session::receive`] gives the tokens of what the last one received back, a copy received again included, so save the session's state between the two. The requests whose time the server checks, an upload's start and a subscription, are signed with the server's clock, a [`ServerClock`] that the transport keeps to the server's time from its responses, e.g. their `Date` ([`Client::with_clock`]), as a device's clock may be off; one refused for its time goes again once. Alice's initial message carries the session's first message, so Bob can write back as soon as he accepts it.

Anyone can send an initial message claiming to be anyone, but only the real sender can have encrypted its first message, as X3DH's keys take the sender's identity key: [`Client::accept`] fails unless it decrypts, and then uses up nothing, so a forged initial message changes nothing. Nothing is signed, so neither peer can prove to others that they talked.

When a known peer starts a new session, or this client does, [`Session::keep`] keeps the old one with it, only to decrypt the messages sent on it: as in Signal's session management (Tahini), an earlier session never becomes the one sent on again, so whoever stole its keys cannot draw the chat back to it once the ratchet has locked them out. Of two sessions the peers start at once, both pick the one with the higher ID. If the peers still miss each other, e.g. as an initial message was lost, the session is retired after a few turns, and the next message goes on a new one ([`Session::needs_new_session`], [`Client::start_again`]); so does it when the client [retires](Session::retire) it, e.g. as the peer deleted the chat. As an initial message reaches the server before its session's messages, but a client takes initial messages and receives in turn, [`Session::receive`] stops at a message that does not decrypt, and goes on past it once the initial messages are taken ([`Session::skip_stalled`]). Until the peer answers a session this client started, each message goes with its initial message, as Signal's clients do, which the peer accepts from there if the one in its inbox was lost ([`Received::initial_messages`]); where receiving stops, those of the rest of the page are offered too. [`Received::earlier`] tells a message that came on an earlier session, e.g. one the peer sent before deleting the chat and starting it again.

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
for received in bob_session.receive().await? {
    println!("{}", String::from_utf8_lossy(&received.content?));
}
bob_session.send(b"Hi Alice").await?;
# Ok(())
# }
```
