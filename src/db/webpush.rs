use rusqlite::{params, Connection, Result};

/// A browser's web push subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub topic: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub created: i64,
}

/// Retrieve the stored VAPID key pair. Returns `None` if none have been
/// generated yet.
pub fn get_vapid_keys(conn: &Connection) -> Result<Option<(String, String)>> {
    let result = conn.query_row(
        "SELECT private, public FROM vapid_keys WHERE id = 'default'",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    );
    match result {
        Ok(pair) => Ok(Some(pair)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist the VAPID key pair, replacing any existing row.
pub fn store_vapid_keys(conn: &Connection, private_pem: &str, public_b64: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO vapid_keys (id, private, public) \
         VALUES ('default', ?1, ?2)",
        params![private_pem, public_b64],
    )?;
    Ok(())
}

/// Insert a new web push subscription record.
pub fn add_subscription(conn: &Connection, sub: &Subscription) -> Result<()> {
    conn.execute(
        "INSERT INTO webpush_subscriptions \
         (id, topic, endpoint, p256dh, auth, created) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![sub.id, sub.topic, sub.endpoint, sub.p256dh, sub.auth, sub.created],
    )?;
    Ok(())
}

/// Delete a subscription by its opaque ID. Returns the number of rows deleted.
pub fn delete_subscription(conn: &Connection, id: &str) -> Result<usize> {
    let n = conn.execute(
        "DELETE FROM webpush_subscriptions WHERE id = ?1",
        params![id],
    )?;
    Ok(n)
}

/// Return all subscriptions registered for a given topic.
pub fn get_subscriptions_for_topic(conn: &Connection, topic: &str) -> Result<Vec<Subscription>> {
    let mut stmt = conn.prepare(
        "SELECT id, topic, endpoint, p256dh, auth, created \
         FROM webpush_subscriptions WHERE topic = ?1",
    )?;
    let subs = stmt
        .query_map(params![topic], |row| {
            Ok(Subscription {
                id: row.get(0)?,
                topic: row.get(1)?,
                endpoint: row.get(2)?,
                p256dh: row.get(3)?,
                auth: row.get(4)?,
                created: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(subs)
}
