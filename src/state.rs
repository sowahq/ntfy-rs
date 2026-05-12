use crate::{config::Config, db::DbPool, topic::TopicMap, visitor::VisitorMap};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: DbPool,
    pub auth_db: Option<DbPool>,
    pub topics: Arc<TopicMap>,
    pub visitors: Arc<VisitorMap>,
    /// Shared HTTP client for upstream poll-forward and future outbound calls.
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config, db: DbPool, auth_db: Option<DbPool>) -> Self {
        let config = Arc::new(config);
        let visitors = Arc::new(VisitorMap::new(Arc::clone(&config)));
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");
        AppState {
            config: Arc::clone(&config),
            db,
            auth_db,
            topics: Arc::new(TopicMap::new()),
            visitors,
            http,
        }
    }

    pub fn effective_auth_db(&self) -> &DbPool {
        self.auth_db.as_ref().unwrap_or(&self.db)
    }
}
