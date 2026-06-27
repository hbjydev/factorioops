use anyhow::anyhow;
use factorioops_core::result::{Result, error::FactorioopsError};
use factorioops_models::user::DbUser;

mod user;

#[derive(Clone)]
pub struct MongoStore {
    client: mongodb::Client,
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
            client,
            user_store: db.collection("users"),
        })
    }

    pub async fn open(uri: String) -> Result<Self> {
        let client = mongodb::Client::with_uri_str(uri)
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        Self::new(client)
    }
}
