//! The Connect calls to the server, e.g. the Cloudflare Worker, over HTTP.

use std::{sync::Arc, time::Duration};

use parking_lot::RwLock;
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
    /// The cookie of this client's sign-in to the server, `name=value`, which storing files
    /// there takes, see [`Http::sign_in`]; shared by the clones.
    cookie: Arc<RwLock<Option<String>>>,
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
            cookie: Arc::default(),
        })
    }

    /// Sign in to the server with its `password`, which storing files there takes, as they cost
    /// it storage: its calls carry the cookie it answers with from then on.
    pub async fn sign_in(&self, password: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .post(format!("{}/auth/password", self.server))
            .body(password.to_string())
            .send()
            .await?;
        match response.status().as_u16() {
            200 => {}
            403 => anyhow::bail!("Wrong password"),
            503 => anyhow::bail!("This server takes no sign-ins: it has no password set"),
            status => anyhow::bail!("The server answered {status}"),
        }
        // `name=value`, without its attributes, as a request's `cookie` header takes it.
        let cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|cookie| cookie.to_str().ok())
            .and_then(|cookie| cookie.split(';').next())
            .ok_or_else(|| anyhow::anyhow!("The server signed nobody in"))?;
        *self.cookie.write() = Some(cookie.to_string());
        Ok(())
    }

    /// Whether this client signed in to the server.
    pub fn signed_in(&self) -> bool {
        self.cookie.read().is_some()
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
        let mut request = self
            .client
            .post(format!("{}{path}", self.server))
            .header("content-type", CONTENT_TYPE)
            .header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION)
            .body(body);
        if let Some(cookie) = self.cookie.read().as_deref() {
            request = request.header("cookie", cookie);
        }
        let response = request.send().await.map_err(failed)?;
        let status = response.status().as_u16();
        Ok((status, response.bytes().await.map_err(failed)?.to_vec()))
    }
}
