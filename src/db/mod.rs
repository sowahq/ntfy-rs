pub mod attachments;
pub mod cache;
pub mod schema;
#[cfg(feature = "auth")]
pub mod users;
#[cfg(feature = "webpush")]
pub mod webpush;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;

pub type DbPool = Pool<SqliteConnectionManager>;

/// Open (or create) the SQLite database and run schema migrations.
pub fn open(path: Option<&PathBuf>) -> anyhow::Result<DbPool> {
    let manager = match path {
        Some(p) => SqliteConnectionManager::file(p),
        None => SqliteConnectionManager::memory(),
    }
    // Apply per-connection PRAGMAs to every pooled connection, not just the
    // migration connection — otherwise foreign-key cascades (e.g. tokens →
    // users) are not enforced on normal request connections.
    //
    // The cache/mmap PRAGMAs are tuned for low-memory hosts:
    //   cache_size = -2000  → ~2 MiB page cache per connection (SQLite default)
    // is lowered to 512 KiB, and mmap is disabled so the DB is not memory-mapped
    // (avoids large virtual/resident memory on tiny machines).
    .with_init(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -512;
             PRAGMA mmap_size = 0;
             PRAGMA temp_store = MEMORY;",
        )
    });

    let pool = Pool::builder()
        // SQLite allows only one writer at a time. Keep the pool small to bound
        // per-connection memory (each connection holds its own page cache).
        // Two connections are plenty for the low-concurrency target deployment.
        .max_size(2)
        .build(manager)?;

    // Run schema migrations on a single connection before handing the pool out.
    {
        let conn = pool.get()?;
        schema::migrate(&conn)?;
    }

    Ok(pool)
}
