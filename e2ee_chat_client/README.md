E2EE chat TUI client. It talks to the [Worker](../e2ee_chat_worker) over Connect, so it chats with the [web client](../e2ee_chat_web) too: both send text and images in the same format.

Files from the web client show with their name and size. Select one in the conversation and press `s` to save it in the `--downloads` directory, under its name without any directory, numbered rather than replacing a file. An attachment, the web client's way to send files over 1 MiB, is downloaded only then, chunk by chunk, waiting for the chunks its sender is still uploading, and takes its name once whole; the server keeps attachments for `RETENTION_DAYS` only.

```sh
An E2EE chat client.

Usage: e2ee_chat_client [OPTIONS] <SERVER_ADDR>

Arguments:
  <SERVER_ADDR>  The E2EE chat server's address, e.g. the Worker's: https://e2ee-chat.example.workers.dev

Options:
      --downloads <DOWNLOADS>  Where saved files go [default: .]
  -h, --help                   Print help
  -V, --version                Print version
```

For a local Worker, run `npx wrangler dev` in `e2ee_chat_worker`, then `e2ee_chat_client http://localhost:8787`.

Its identity and sessions live in memory only, until it quits.
