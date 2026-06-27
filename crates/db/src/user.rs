use anyhow::anyhow;
use async_trait::async_trait;
use factorioops_core::result::{Result, error::FactorioopsError};
use factorioops_models::user::{DbUser, UserStore};
use ulid::Ulid;
use futures::stream::TryStreamExt;

use crate::MongoStore;

#[async_trait]
impl UserStore for MongoStore {
    async fn list_users(
        &self,
        filters: Option<Vec<factorioops_models::user::UserFilter>>,
        pagination: Option<factorioops_models::PaginationOptions>,
    ) -> Result<Vec<factorioops_models::user::DbUser>> {
        let mut query = mongodb::bson::Document::new();

        if let Some(filters) = filters {
            for filter in filters {
                if let Some(ids) = filter.id {
                    let id_strings: Vec<String> = ids.into_iter().map(|id| id.to_string()).collect();
                    query.insert("id", mongodb::bson::doc! { "$in": id_strings });
                }
                if let Some(usernames) = filter.username {
                    query.insert("username", mongodb::bson::doc! { "$in": usernames });
                }
                if let Some(emails) = filter.email {
                    query.insert("email", mongodb::bson::doc! { "$in": emails });
                }
            }
        }

        let mut find_options = mongodb::options::FindOptions::default();

        let limit = pagination.and_then(|p| p.limit).unwrap_or(50);
        find_options.limit = Some(limit);

        let cursor = self
            .user_store
            .find(query)
            .with_options(find_options)
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        let users: Vec<DbUser> = cursor
            .try_collect()
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        Ok(users)
    }

    async fn create_user(
        &self,
        user: factorioops_models::user::DbUser,
    ) -> Result<()> {
        self.user_store
            .insert_one(user)
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        Ok(())
    }

    async fn update_user(
        &self,
        user: factorioops_models::user::DbUser,
    ) -> Result<()> {
        if user.id.is_nil() {
            return Err(FactorioopsError::Other(anyhow!("User ID is required for update")));
        }

        self.user_store
            .replace_one(
                mongodb::bson::doc! { "id": user.id.to_string() },
                user,
            )
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        Ok(())
    }

    async fn delete_user(&self, id: Ulid) -> Result<()> {
        if id.is_nil() {
            return Err(FactorioopsError::Other(anyhow!("User ID is required for deletion")));
        }

        self.user_store
            .delete_one(mongodb::bson::doc! { "id": id.to_string() })
            .await
            .map_err(|e| FactorioopsError::Other(e.into()))?;

        Ok(())
    }
}
