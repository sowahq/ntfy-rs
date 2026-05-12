//! iOS upstream poll-forward.
//!
//! When a message is published to a self-hosted ntfy-rs server, iOS clients
//! cannot receive push notifications directly because APNs requires a trusted
//! intermediary (ntfy.sh or a custom FCM project). The workaround is to send
//! a lightweight "poll request" to the upstream server on each publish. The
//! upstream server then triggers an APNs wake via FCM, and the iOS app wakes
//! and polls the self-hosted server for the actual message content.
//!
//! The poll request is a PUT to `{upstream_base_url}/{sha256(topic)}` with a
//! minimal body. The upstream server never sees the message content.

use crate::config::Config;
use sha2::{Digest, Sha256};

/// Fire-and-forget: forward a poll request to the upstream server.
/// Errors are logged and swallowed — upstream failure must never fail a publish.
pub async fn forward_poll(config: &Config, topic: &str, client: &reqwest::Client) {
    let base = match &config.upstream_base_url {
        Some(b) => b.trim_end_matches('/').to_string(),
        None => return, // upstream not configured
    };

    // Hash the topic so the upstream server never learns the actual topic name.
    let topic_hash = sha256_hex(topic);
    let url = format!("{base}/{topic_hash}");

    let mut req = client
        .put(&url)
        .header("Content-Type", "text/plain")
        // Minimal body — upstream only needs to know a message arrived.
        .body("New message");

    if let Some(token) = &config.upstream_access_token {
        req = req.bearer_auth(token);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(topic = %topic, upstream = %url, "poll-forward sent");
        }
        Ok(resp) => {
            tracing::warn!(
                topic = %topic,
                upstream = %url,
                status = %resp.status(),
                "poll-forward non-2xx response"
            );
        }
        Err(e) => {
            tracing::warn!(topic = %topic, upstream = %url, error = %e, "poll-forward failed");
        }
    }
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher
        .finalize()
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
