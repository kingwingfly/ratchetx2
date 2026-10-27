-- A message keeps the initial message its sender sent with it, while its session was unanswered.
ALTER TABLE messages ADD COLUMN initial_message BLOB;
