The E2EE chat's client flow: X3DH / PQXDH over the [handshake](../protocol) service (`handshake.v2`), then a double ratchet ([party](../party)) over the mailbox service (`mailbox.v2`).

- [`Client`] is an identity on a handshake server. It publishes signed capability manifests and prekeys ([`Client::publish_v2`], [`Client::refill_prekeys_v2`]), starts sessions ([`Client::initiate_v2`] / [`Client::prepare_initiate_v2`]), and non-destructively lists, accepts, and acknowledges initial messages ([`Client::list_initial_messages_v2`], [`Client::accept_initial_v2`], [`Client::ack_initial_messages_v2`], or [`Client::list_and_accept_v2`]).
- [`Session`] is a conversation with one peer. It encrypts, pushes idempotently ([`Session::push_v2`]), and performs recipient-signed mailbox fetches ([`Session::receive_v2`]).

Both take any client of the [protocol](../protocol) traits, so the same flow runs over Connect, in-process, or a transport of your own. A message leaves the server once its recipient has it: [`Session::encrypt`] gives, with the message, SHA-256 of its delivery token, HMAC-SHA256 of its encrypted header under a key from the session's shared secret, which only the two peers can compute; [`Session::push_v2`] gives the server that hash and a deterministic idempotency ID, and the recipient's next [`Session::receive_v2`] gives the tokens of what the last one received back, a copy received again included, so save the session's state between the two. Signed v2 requests (`PublishV2`, `RefillPrekeys`, `ListInitialMessages`, `AckInitialMessages`, `FetchSigned`) and audience-bound notification subscriptions ([`Client::subscription_for_audience`]) are bound to the relay's canonical audience and signed with the server's clock, a [`ServerClock`] that the transport keeps to the server's time from its responses, e.g. their `Date` ([`Client::with_clock`]), as a device's clock may be off. An attachment's upload starts unsigned, with SHA-256 of its delete token, which [`attachment::delete_token`] derives from its key, so that either peer can delete it with [`attachment::delete`], at any time. Alice's initial message carries the session's first message, so Bob can write back as soon as he accepts it.

Anyone can send an initial message claiming to be anyone, but only the real sender can have encrypted its first message, as X3DH/PQXDH's keys take the sender's identity key: [`Client::accept_initial_v2`] fails unless it decrypts, and then uses up nothing, so a forged initial message changes nothing. Nothing is signed in the handshake itself, so neither peer can prove to others that they talked.

When a known peer starts a new session, or this client does, [`Session::keep`] keeps the old one with it, only to decrypt the messages sent on it: as in Signal's session management (Tahini), an earlier session never becomes the one sent on again, so whoever stole its keys cannot draw the chat back to it once the ratchet has locked them out. Of two sessions the peers start at once, both pick the one with the higher ID. If the peers still miss each other, e.g. as an initial message was lost, the session is retired after a few turns, and the next message goes on a new one ([`Session::needs_new_session`], [`Client::start_again_v2`]); so does it when the client [retires](Session::retire) it, e.g. as the peer deleted the chat. As an initial message reaches the server before its session's messages, but a client lists initial messages and receives in turn, [`Session::receive_v2`] stops at a message that does not decrypt, and goes on past it once the initial messages are processed ([`Session::skip_stalled`]). Until the peer answers a session this client started, each message goes with its initial message, as Signal's clients do, which the peer accepts from there if the one in its inbox was lost ([`ReceivedV2::initial_messages`]); where receiving stops, those of the rest of the page are offered too. [`ReceivedV2::earlier`] tells a message that came on an earlier session, e.g. one the peer sent before deleting the chat and starting it again.

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
use session::{AcceptedInitial, Client, PeerPqState};
use session::protocol::connect::{ConnectClient, Post};

/// Posts the calls with the HTTP client of your choice, e.g. reqwest, or `fetch` in a browser.
#[derive(Clone)]
struct Http;

impl Post for Http {
    async fn post(&self, path: &str, body: Vec<u8>) -> session::protocol::Result<(u16, Vec<u8>)> {
        // POST `body` to the server's address and `path`, e.g.
        // https://chat.example.com/mailbox.v2.MailboxService/PushV2, with the headers
        // `Content-Type: application/proto` and `Connect-Protocol-Version: 1`, and return the
        // response's status and body.
#       unimplemented!()
    }
}

# async fn run() -> session::Result<()> {
let audience = "chat.example.com";
let server = ConnectClient::new(Http);
let mut alice = Client::new(server.clone());
let mut bob = Client::new(server.clone());

// Bob publishes his v2 prekeys and signed capability manifest; Alice starts a session, saying hi,
// and pushes a message.
bob.publish_v2(audience, 10, 10).await?;
let mut alice_session = alice
    .initiate_v2(
        audience,
        &bob.identity_key(),
        &PeerPqState::default(),
        b"Hi Bob",
        server.clone(),
    )
    .await?;
let question = alice_session.encrypt(b"How are you?")?;
alice_session.push_v2(question).await?;

// Bob lists and accepts pending initial messages, then receives and replies over v2.
let accepted = bob
    .list_and_accept_v2(audience, 10, server, |_| PeerPqState::default())
    .await?;
let (_, AcceptedInitial::Accepted { session: mut bob_session, first_message: hi, .. }) =
    accepted.outcomes.into_iter().next().expect("initial message")
else {
    unreachable!()
};
println!("{}", String::from_utf8_lossy(&hi));
for received in bob_session.receive_v2(&bob, audience).await? {
    println!("{}", String::from_utf8_lossy(&received.content?));
}
let reply = bob_session.encrypt(b"Hi Alice")?;
bob_session.push_v2(reply).await?;
# Ok(())
# }
```
