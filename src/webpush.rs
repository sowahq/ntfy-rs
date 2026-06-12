//! Web Push notification support.
//!
//! Implements RFC 8291 (Message Encryption for Web Push),
//! RFC 8188 (Encrypted Content-Encoding: aes128gcm), and
//! RFC 8292 (Voluntary Application Server Identification — VAPID).
//!
//! Pure Rust: uses p256 (ECDH + ECDSA), aes-gcm, hkdf, and sha2.
//! No OpenSSL dependency.

use crate::{
    db::{webpush as db_wp, DbPool},
    message::Message,
};
use aes_gcm::{
    aead::Aead,
    Aes128Gcm, KeyInit, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

// ── Public types ─────────────────────────────────────────────────────────────

/// Server-side VAPID state. Held in `AppState` and shared across requests.
#[derive(Clone)]
pub struct VapidState {
    /// Base64url-encoded uncompressed P-256 public key (65 bytes: 0x04 ‖ X ‖ Y).
    ///
    /// This is the value browsers pass to `pushManager.subscribe({
    ///   applicationServerKey: publicKey })`.
    pub public_key_b64: String,

    /// Pre-parsed ECDSA signing key used for VAPID JWT generation.
    pub(crate) signing_key: Arc<SigningKey>,
}

impl VapidState {
    fn from_pem(private_pem: &str, public_key_b64: &str) -> Result<Self> {
        let secret =
            SecretKey::from_pkcs8_pem(private_pem).context("invalid VAPID PKCS8 PEM")?;
        let signing_key = SigningKey::from(&secret);
        Ok(VapidState {
            public_key_b64: public_key_b64.to_string(),
            signing_key: Arc::new(signing_key),
        })
    }
}

// ── Initialisation ───────────────────────────────────────────────────────────

/// Load existing VAPID keys from the database, or generate and persist a new
/// P-256 key pair if none exist yet.
pub fn load_or_generate(db: &DbPool) -> Result<VapidState> {
    let conn = db.get().context("failed to get DB connection")?;

    if let Some((private_pem, public_b64)) = db_wp::get_vapid_keys(&conn)? {
        return VapidState::from_pem(&private_pem, &public_b64);
    }

    // Generate a fresh P-256 key pair.
    let secret = SecretKey::random(&mut OsRng);

    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to PKCS8-encode VAPID private key")?
        .to_string();

    // Uncompressed public key: 0x04 ‖ X ‖ Y (65 bytes), base64url-encoded.
    let pub_point = secret.public_key().to_encoded_point(false);
    let public_b64 = URL_SAFE_NO_PAD.encode(pub_point.as_bytes());

    db_wp::store_vapid_keys(&conn, &private_pem, &public_b64)
        .context("failed to store VAPID keys")?;

    tracing::info!("Generated new VAPID key pair");
    VapidState::from_pem(&private_pem, &public_b64)
}

// ── Notification dispatch ────────────────────────────────────────────────────

/// Send a web push notification to all subscribers of `topic`.
///
/// Errors per subscription are logged and swallowed so that a failing push
/// service cannot block the publish pipeline.
pub async fn send_notifications(
    http: &reqwest::Client,
    vapid: &Arc<VapidState>,
    db: &DbPool,
    topic: &str,
    msg: &Message,
) {
    let subs = match db
        .get()
        .ok()
        .and_then(|c| db_wp::get_subscriptions_for_topic(&c, topic).ok())
    {
        Some(s) => s,
        None => return,
    };

    if subs.is_empty() {
        return;
    }

    let payload = build_payload(msg);

    for sub in &subs {
        match send_one(http, vapid, sub, &payload).await {
            Ok(()) => {}
            Err(e) => {
                // Log only the host, not the full endpoint URL: push endpoints
                // embed a per-subscription credential in the path/query.
                let endpoint_host = reqwest::Url::parse(&sub.endpoint)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .unwrap_or_default();
                tracing::warn!(
                    sub_id        = %sub.id,
                    endpoint_host = %endpoint_host,
                    error         = %e,
                    "web push failed"
                );
            }
        }
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn build_payload(msg: &Message) -> String {
    let title = if msg.title.is_empty() {
        &msg.topic
    } else {
        &msg.title
    };
    serde_json::json!({
        "id":       msg.id,
        "time":     msg.time,
        "event":    "message",
        "topic":    msg.topic,
        "title":    title,
        "message":  msg.message,
        "priority": msg.priority,
        "tags":     msg.tags,
        "click":    msg.click,
    })
    .to_string()
}

async fn send_one(
    http: &reqwest::Client,
    vapid: &Arc<VapidState>,
    sub: &db_wp::Subscription,
    payload: &str,
) -> Result<()> {
    let body = encrypt_payload(payload.as_bytes(), &sub.p256dh, &sub.auth)?;
    let auth_header = build_vapid_jwt(vapid, &sub.endpoint)?;

    let resp = http
        .post(&sub.endpoint)
        .header("TTL", "2419200") // 28 days
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", &auth_header)
        .body(body)
        .send()
        .await
        .context("push request failed")?;

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }

    let text = resp.text().await.unwrap_or_default();
    Err(anyhow!("push service returned {}: {}", status, text))
}

/// RFC 8291 §4 + RFC 8188 §2: encrypt `content` for the given subscription.
///
/// Returns the complete `aes128gcm` binary body:
/// `salt (16) ‖ rs (4, big-endian) ‖ idlen (1) ‖ keyid (65) ‖ ciphertext`
fn encrypt_payload(
    content: &[u8],
    client_p256dh_b64: &str,
    client_auth_b64: &str,
) -> Result<Vec<u8>> {
    // ── Decode subscription keys ──────────────────────────────────────────
    let client_pub_bytes = URL_SAFE_NO_PAD
        .decode(client_p256dh_b64)
        .context("invalid p256dh encoding")?;
    let client_pub =
        PublicKey::from_sec1_bytes(&client_pub_bytes).map_err(|e| anyhow!("bad p256dh: {e}"))?;

    let auth_secret = URL_SAFE_NO_PAD
        .decode(client_auth_b64)
        .context("invalid auth encoding")?;
    if auth_secret.len() != 16 {
        return Err(anyhow!(
            "auth secret must be 16 bytes, got {}",
            auth_secret.len()
        ));
    }

    // ── Ephemeral server key pair ─────────────────────────────────────────
    let server_ephem = EphemeralSecret::random(&mut OsRng);
    let server_ephem_pub = server_ephem.public_key();
    let server_ephem_pub_enc = server_ephem_pub.to_encoded_point(false); // 65 bytes
    let server_ephem_pub_bytes = server_ephem_pub_enc.as_bytes();

    // ── ECDH shared secret ────────────────────────────────────────────────
    let ecdh = server_ephem.diffie_hellman(&client_pub);
    let ecdh_bytes = ecdh.raw_secret_bytes(); // 32-byte x-coordinate

    // ── RFC 8291 §4: PRK_key + IKM ───────────────────────────────────────
    //   PRK_key = HKDF-Extract(salt=auth_secret, IKM=ecdh_bytes)
    //   auth_info = "WebPush: info\0" ‖ ua_public (65) ‖ as_public (65)
    //   IKM = HKDF-Expand(PRK_key, auth_info, 32)
    let hk1 = Hkdf::<Sha256>::new(Some(&auth_secret), ecdh_bytes.as_slice());
    let mut auth_info = Vec::with_capacity(14 + 65 + 65);
    auth_info.extend_from_slice(b"WebPush: info\x00");
    auth_info.extend_from_slice(&client_pub_bytes);
    auth_info.extend_from_slice(server_ephem_pub_bytes);
    let mut ikm = [0u8; 32];
    hk1.expand(&auth_info, &mut ikm)
        .expect("HKDF expand to 32 bytes always succeeds");

    // ── RFC 8188 §2.2: CEK + nonce from random salt ───────────────────────
    //   PRK   = HKDF-Extract(salt=salt_16, IKM=ikm)
    //   CEK   = HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0", 16)
    //   NONCE = HKDF-Expand(PRK, "Content-Encoding: nonce\0",     12)
    use rand::RngCore;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let hk2 = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    hk2.expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .expect("HKDF expand to 16 bytes always succeeds");
    hk2.expand(b"Content-Encoding: nonce\x00", &mut nonce_bytes)
        .expect("HKDF expand to 12 bytes always succeeds");

    // ── AES-128-GCM ───────────────────────────────────────────────────────
    // Plaintext = content ‖ 0x02 (last-record delimiter per RFC 8188)
    let cipher =
        Aes128Gcm::new_from_slice(&cek).map_err(|e| anyhow!("AES-GCM key error: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plaintext = content.to_vec();
    plaintext.push(0x02);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;

    // ── Build content structure ───────────────────────────────────────────
    // salt (16) ‖ rs=4096 (4, big-endian) ‖ idlen=65 (1) ‖ keyid (65) ‖ ciphertext
    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(65u8);
    body.extend_from_slice(server_ephem_pub_bytes);
    body.extend_from_slice(&ciphertext);

    Ok(body)
}

/// Build the `Authorization: vapid t=<jwt>,k=<pubkey>` header value.
///
/// The JWT is signed with ES256 (P-256 ECDSA + SHA-256, deterministic per
/// RFC 6979) and valid for 12 hours.
fn build_vapid_jwt(vapid: &Arc<VapidState>, endpoint: &str) -> Result<String> {
    let audience = parse_audience(endpoint)?;

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 43_200; // 12 hours

    let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "aud": audience,
            "exp": exp,
            "sub": "mailto:admin@localhost",
        })
        .to_string(),
    );

    let signing_input = format!("{header}.{claims}");

    // Deterministic P-256 ECDSA (RFC 6979) — SHA-256 applied internally.
    let sig: Signature = vapid.signing_key.sign(signing_input.as_bytes());

    // JWT requires the raw (r ‖ s) 64-byte signature, not DER.
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let jwt = format!("{signing_input}.{sig_b64}");
    Ok(format!("vapid t={jwt},k={}", vapid.public_key_b64))
}

/// Extract `scheme://host` from a full push endpoint URL without pulling in
/// a URL-parsing dependency (the `url` crate is already a transitive dep via
/// reqwest, but we avoid a direct dep for this simple case).
fn parse_audience(endpoint: &str) -> Result<String> {
    let (scheme, rest) = if let Some(r) = endpoint.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = endpoint.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(anyhow!("push endpoint must use https://"));
    };
    let host = rest.split('/').next().unwrap_or(rest);
    Ok(format!("{scheme}://{host}"))
}
