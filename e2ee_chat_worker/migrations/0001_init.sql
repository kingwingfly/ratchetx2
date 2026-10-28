-- The handshake, mailbox and attachment stores. Keys are 32-byte BLOBs, timestamps milliseconds
-- since the Unix epoch.

-- Each identity's published bundle.
CREATE TABLE bundles (
    identity_key BLOB PRIMARY KEY,
    signed_prekey BLOB NOT NULL,
    signed_prekey_signature BLOB NOT NULL,
    -- The publish request's timestamp; the next publish must be newer.
    timestamp INTEGER NOT NULL
) WITHOUT ROWID;

-- The one-time prekeys of each bundle that nobody took yet, taken in order of position.
CREATE TABLE one_time_prekeys (
    identity_key BLOB NOT NULL,
    position INTEGER NOT NULL,
    prekey BLOB NOT NULL,
    PRIMARY KEY (identity_key, position)
) WITHOUT ROWID;

-- The timestamp of each inbox's last take; the next take must be newer.
CREATE TABLE inboxes (
    recipient BLOB PRIMARY KEY,
    last_take INTEGER NOT NULL
) WITHOUT ROWID;

-- Initial messages waiting in their recipient's inbox, oldest first by id.
CREATE TABLE initial_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient BLOB NOT NULL,
    sender BLOB NOT NULL,
    ephemeral_key BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    one_time_prekey BLOB,
    -- The session's first message, which the recipient checks.
    header BLOB NOT NULL,
    content BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX initial_messages_by_recipient ON initial_messages (recipient, id);
CREATE INDEX initial_messages_by_age ON initial_messages (created_at);

-- The last sequence number of each queue, so that numbers are not reused once messages expire.
CREATE TABLE queues (
    sender BLOB NOT NULL,
    recipient BLOB NOT NULL,
    last_sequence INTEGER NOT NULL,
    PRIMARY KEY (sender, recipient)
) WITHOUT ROWID;

-- The messages of each queue, until their recipient has them. A large content is in R2, named by
-- `object`, instead of `content`.
CREATE TABLE messages (
    sender BLOB NOT NULL,
    recipient BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    header BLOB NOT NULL,
    content BLOB,
    object TEXT,
    -- The content's length, wherever it is.
    size INTEGER NOT NULL,
    -- The initial message its sender sent with it, while its session was unanswered.
    initial_message BLOB,
    -- SHA-256 of its delivery token, which its recipient gives back once it has it, deleting
    -- it; none for one that only expires.
    delivery_hash BLOB,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, recipient, sequence),
    CHECK ((content IS NULL) != (object IS NULL))
) WITHOUT ROWID;
CREATE INDEX messages_by_age ON messages (created_at);

-- Attachments: their chunks are R2 objects named attachments/<id>/<index>, uploaded with the
-- token whose SHA-256 is kept here.
CREATE TABLE attachments (
    id BLOB PRIMARY KEY,
    uploader BLOB NOT NULL,
    chunks INTEGER NOT NULL,
    token_hash BLOB NOT NULL,
    -- The chunks put so far, chunk i as bit i: one put and gone from R2 since, as the bucket's
    -- lifecycle rules deleted it, expired, rather than is still to come.
    uploaded INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX attachments_by_age ON attachments (created_at);
