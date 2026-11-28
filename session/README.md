The E2EE chat's client flow: X3DH / PQXDH over the [handshake](../protocol) service (`handshake.v2`), then a double ratchet ([party](../party)) over the sealed-sender-lite unified mailbox service (`mailbox.v2`).

- [`Client`] is an identity on a handshake and mailbox relay. It publishes signed capability manifests and prekeys ([`Client::publish_v2`], [`Client::refill_prekeys_v2`]), starts sessions ([`Client::initiate_v2`] / [`Client::prepare_initiate_v2`] or lock-free [`claim_peer_bundle_v2`] + [`Client::finish_prepare_initiate_v2`]), cursor-paginates, synchronously accepts, and acknowledges initial messages ([`Client::list_initial_messages_v2`], [`Client::accept_listed_v2`], [`Client::accept_initial_v2`], [`Client::ack_initial_messages_v2`]), manages per-peer deniable write-token grants ([`Client::register_write_token_v2`], [`Client::revoke_write_token_v2`]), and reads/acknowledges the unified recipient mailbox ([`Client::fetch_mailbox_v2`], [`Client::commit_mailbox_page`], [`Client::ack_mailbox_v2`]).
- [`Session`] is a conversation with one peer. It encrypts ([`Session::encrypt`], capturing the sealing session's deniable write token and carried initial message onto [`Sealed`]), pushes idempotently ([`Session::push_v2`]), exposes `inbound_token_hashes` for O(1) unified mailbox dispatch ([`Session::inbound_token_hashes`], [`Session::active_inbound_token_hash`]), and decrypts fetched envelopes synchronously ([`Session::decrypt_envelope`]).

Both take any client of the [protocol](../protocol) traits, so the same flow runs over Connect, in-process, or a transport of your own. Each session derives directional deniable 32-byte write tokens from its X3DH/PQXDH shared secret (`HKDF-SHA256(None, SK, "session.v2/write-token\0" || sender || recipient)`); the recipient registers `SHA-256(t_{peer->me})` under an opaque `peer_slot_id` ([`Client::peer_slot_id`]) so the relay remains blind to the sender while enforcing human-approved bulk delivery. Signed v2 requests (`PublishV2`, `RefillPrekeys`, `ListInitialMessages`, `AckInitialMessages`, `FetchSigned`, `AckMessages`, `RegisterWriteToken`, `RevokeWriteToken`) and audience- and nonce-bound notification subscriptions ([`Client::subscription_for_audience`]) are bound to the relay's canonical audience and signed with the server's clock, a [`ServerClock`] that the transport keeps to the server's time from its responses, e.g. their `Date` ([`Client::with_clock`]), as a device's clock may be off. An attachment's upload starts unsigned, with SHA-256 of its delete token, which [`attachment::delete_token`] derives from its key, so that either peer can delete it with [`attachment::delete`], at any time. Alice's initial message carries the session's first message, so Bob can write back as soon as he accepts it.

Anyone can send an initial message claiming to be anyone, but only the real sender can have encrypted its first message, as X3DH/PQXDH's keys take the sender's identity key: [`Client::accept_initial_v2`] fails unless it decrypts, and then uses up nothing, so a forged initial message changes nothing. Nothing is signed in the handshake itself, so neither peer can prove to others that they talked.

When a known peer starts a new session, or this client does, [`Session::keep`] keeps the old one with it (along with its `inbound_token_hash` for O(1) routing), only to decrypt the messages sent on it: as in Signal's session management (Tahini), an earlier session never becomes the one sent on again, so whoever stole its keys cannot draw the chat back to it once the ratchet has locked them out. Of two sessions the peers start at once, both pick the PQ one or the one with the higher ID. If the peers still miss each other, e.g. as an initial message was lost, the session is retired after a few turns, and the next message goes on a new one ([`Session::needs_new_session`], [`Client::start_again_v2`]); so does it when the client [retires](Session::retire) it, e.g. as the peer deleted the chat. Until the peer answers a session this client started, each [`Sealed`] message captures its initial message at seal time, as Signal's clients do, which the peer accepts from the envelope if the one in its inbox was lost. [`DecryptedMessage::earlier`] tells a message that came on an earlier session, e.g. one the peer sent before deleting the chat and starting it again.

Files too large for a message go as attachments ([`attachment`]): [`Client::start_upload`] starts one under a new key, its chunks are encrypted and uploaded, and a message carries the attachment's ID and key, so that its recipients download and decrypt the chunks.

To check that nobody swapped an identity key between two peers, e.g. a server in the middle, they compare their [`safety_number`] out of band: 60 digits, computed as Signal's are, the same on both sides only if each has the other's real key.

To keep them between runs, save their states ([`Client::state`], [`Session::state`]) and restore them with [`Client::restore`] and [`Session::restore`]. Use the `prost` feature for the portable, versioned protobuf persistence format (or `serde`), as the features below enable. They hold private keys, so keep them secret, e.g. encrypted.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **prost**: portable, versioned protobuf persistence format for [`ClientState`] and [`SessionState`], defined in `proto/session.proto` (package `session.v1`), in the `proto` module; they are zeroized on drop.
- **serde**: serialize [`ClientState`] and [`SessionState`].
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

// Both publish v2 prekeys and signed capability manifests; Alice initiates and pre-registers
// Bob's reply write token on her relay.
alice.publish_v2(audience, 10, 10).await?;
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
let alice_ver = alice.allocate_grant_version()?;
alice
    .register_write_token_v2(
        &server,
        audience,
        &bob.identity_key(),
        &alice_session.active_inbound_token_hash().unwrap(),
        alice_ver,
        true,
    )
    .await?;

// Bob lists and synchronously accepts pending initial messages, persists, acks the inbox,
// and approves Alice by registering her write token on his relay.
let listed = bob.list_initial_messages_v2(audience, 0, 10).await?;
let batch = bob.accept_listed_v2(&listed, server.clone(), |_| PeerPqState::default());
bob.ack_initial_messages_v2(audience, batch.ack_ids).await?;
let (_, AcceptedInitial::Accepted { session: mut bob_session, first_message: hi, .. }) =
    batch.outcomes.into_iter().next().expect("initial message")
else {
    unreachable!()
};
println!("{}", String::from_utf8_lossy(&hi));
let bob_ver = bob.allocate_grant_version()?;
bob.register_write_token_v2(
    &server,
    audience,
    &alice.identity_key(),
    &bob_session.active_inbound_token_hash().unwrap(),
    bob_ver,
    true,
)
.await?;

// Alice pushes a sealed message; Bob fetches his unified mailbox, decrypts, commits, and ACKs.
let question = alice_session.encrypt(b"How are you?")?;
alice_session.push_v2(&question).await?;
let page = bob.fetch_mailbox_v2(&server, audience, 100).await?;
for env in &page.messages {
    let decrypted = bob_session.decrypt_envelope(env.message.as_ref().unwrap())?;
    println!("{}", String::from_utf8_lossy(&decrypted.content));
}
if let Some(last) = page.last_sequence() {
    bob.commit_mailbox_page(last, last)?;
    bob.ack_mailbox_v2(&server, audience).await?;
}
let reply = bob_session.encrypt(b"Hi Alice")?;
bob_session.push_v2(&reply).await?;
# Ok(())
# }
```
