-- Attachments: their chunks are R2 objects named attachments/<id>/<index>, uploaded with the
-- token whose SHA-256 is kept here.
CREATE TABLE attachments (
    id BLOB PRIMARY KEY,
    uploader BLOB NOT NULL,
    chunks INTEGER NOT NULL,
    token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX attachments_by_age ON attachments (created_at);
