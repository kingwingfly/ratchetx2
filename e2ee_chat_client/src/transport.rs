//! The Connect calls to the server, e.g. the Cloudflare Worker, over HTTP.

use std::time::Duration;

use session::protocol::{
    self, Error, ErrorKind,
    connect::{CONTENT_TYPE, ConnectClient, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER, Post},
};

/// The handshake and mailbox client of the server.
pub type Connect = ConnectClient<Http>;

/// How long a call may take; a push of a large image takes a while.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Posts to the server with reqwest.
#[derive(Debug, Clone)]
pub struct Http {
    client: reqwest::Client,
    /// The server's address, without a trailing slash, e.g. `https://chat.example.com`.
    server: String,
}

impl Http {
    /// Posts to `server`, an `http` or `https` address.
    pub fn new(server: &str) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(server)?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "the server address must start with http:// or https://"
        );
        Ok(Self {
            client: reqwest::Client::builder().timeout(TIMEOUT).build()?,
            // As parsed, e.g. with the scheme in lowercase, which the settings check.
            server: url.as_str().trim_end_matches('/').to_string(),
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn connect(&self) -> Connect {
        ConnectClient::new(self.clone())
    }
}

impl Post for Http {
    async fn post(&self, path: &str, body: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
        let failed = |e| Error::new(ErrorKind::Connect, e);
        let response = self
            .client
            .post(format!("{}{path}", self.server))
            .header("content-type", CONTENT_TYPE)
            .header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION)
            .body(body)
            .send()
            .await
            .map_err(failed)?;
        let status = response.status().as_u16();
        Ok((status, response.bytes().await.map_err(failed)?.to_vec()))
    }
}
