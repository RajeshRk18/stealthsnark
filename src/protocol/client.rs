use anyhow::Result;

use super::messages::{ProveRequest, ProveResponse, SetupRequest};
use super::server::{ProveEnvelope, SetupEnvelope};

/// HTTP client for communicating with the EMSM server.
pub struct EmsmClient {
    base_url: String,
    session_id: String,
    client: reqwest::Client,
}

impl EmsmClient {
    pub fn new(base_url: &str, session_id: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            session_id,
            client: reqwest::Client::new(),
        }
    }

    /// Send setup request: transmit generators to server.
    pub async fn send_setup(&self, request: &SetupRequest) -> Result<()> {
        let url = format!("{}/setup", self.base_url);
        let inner = bincode::serialize(request)?;
        let envelope = SetupEnvelope {
            session_id: self.session_id.clone(),
            request: inner,
        };
        let body = bincode::serialize(&envelope)?;

        let resp = self
            .client
            .post(&url)
            .body(body)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Setup failed with status: {}", resp.status());
        }

        Ok(())
    }

    /// Send prove request: transmit masked vectors, receive MSM results.
    pub async fn send_prove(&self, request: &ProveRequest) -> Result<ProveResponse> {
        let url = format!("{}/prove", self.base_url);
        let inner = bincode::serialize(request)?;
        let envelope = ProveEnvelope {
            session_id: self.session_id.clone(),
            request: inner,
        };
        let body = bincode::serialize(&envelope)?;

        let resp = self
            .client
            .post(&url)
            .body(body)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Prove failed with status: {}", resp.status());
        }

        let bytes = resp.bytes().await?;
        let response: ProveResponse = bincode::deserialize(&bytes)?;
        Ok(response)
    }
}
