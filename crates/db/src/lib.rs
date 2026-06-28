use std::time::Duration;

use anyhow::anyhow;
use factorioops_core::result::{Result, error::FactorioopsError};
use factorioops_models::user::DbUser;
use mongodb::options::ClientOptions;

mod user;

#[derive(Clone)]
pub struct MongoStore {
    _client: mongodb::Client,
    user_store: mongodb::Collection<DbUser>,
}

impl MongoStore {
    pub fn new(client: mongodb::Client) -> Result<Self> {
        let db = client.default_database();
        if db.is_none() {
            return Err(anyhow!("MongoDB client must have a default database set").into());
        }
        let db = db.unwrap();

        Ok(Self {
            _client: client,
            user_store: db.collection("users"),
        })
    }

    pub async fn open(uri: String) -> Result<Self> {
        let mut opts = ClientOptions::parse(uri)
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        if opts.connect_timeout.is_none() {
            opts.connect_timeout = Some(Duration::from_secs(5));
        }

        if opts.max_idle_time.is_none() {
            opts.max_idle_time = Some(Duration::from_secs(10));
        }

        if opts.server_selection_timeout.is_none() {
            opts.server_selection_timeout = Some(Duration::from_secs(5));
        }

        let client =
            mongodb::Client::with_options(opts).map_err(|e| FactorioopsError::Other(e.into()))?;

        Self::new(client)
    }
}
