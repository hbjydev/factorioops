use async_trait::async_trait;
use chrono::DateTime;
use factorioops_core::result::Result;
use ulid::Ulid;

use crate::PaginationOptions;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "bson", derive(serde::Serialize, serde::Deserialize))]
pub struct DbUser {
    pub id: Ulid,
    pub username: String,
    pub password_hash: String,
    pub email: String,
}

impl DbUser {
    pub fn new(username: String, password_hash: String, email: String) -> Self {
        Self {
            id: Ulid::new(),
            username,
            password_hash,
            email,
        }
    }

    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        let timestamp = self.id.timestamp_ms();
        DateTime::from_timestamp_millis(timestamp.cast_signed()).unwrap_or_else(|| {
            tracing::error!("Failed to convert ULID timestamp to DateTime");
            DateTime::from_timestamp_nanos(0)
        })
    }
}

pub struct UserFilter {
    pub id: Option<Vec<Ulid>>,
    pub username: Option<Vec<String>>,
    pub email: Option<Vec<String>>,
}

#[async_trait]
pub trait UserStore {
    /// Gets a user by their ID.
    async fn get_user(&self, id: Ulid) -> Result<Option<DbUser>> {
        let users = self
            .list_users(
                Some(vec![UserFilter {
                    id: Some(vec![id]),
                    username: None,
                    email: None,
                }]),
                Some(PaginationOptions { limit: Some(1) }),
            )
            .await?;

        Ok(users.first().cloned())
    }

    /// Gets a user by their username.
    async fn get_user_by_username(&self, username: String) -> Result<Option<DbUser>> {
        let users = self
            .list_users(
                Some(vec![UserFilter {
                    id: None,
                    username: Some(vec![username]),
                    email: None,
                }]),
                Some(PaginationOptions { limit: Some(1) }),
            )
            .await?;

        Ok(users.first().cloned())
    }

    /// Gets a user by their email.
    async fn get_user_by_email(&self, email: String) -> Result<Option<DbUser>> {
        let users = self
            .list_users(
                Some(vec![UserFilter {
                    id: None,
                    username: None,
                    email: Some(vec![email]),
                }]),
                Some(PaginationOptions { limit: Some(1) }),
            )
            .await?;

        Ok(users.first().cloned())
    }

    /// Lists users in the store, optionally filtered by the provided filters.
    async fn list_users(
        &self,
        filters: Option<Vec<UserFilter>>,
        pagination: Option<PaginationOptions>,
    ) -> Result<Vec<DbUser>>;

    /// Creates a new user in the store.
    async fn create_user(&self, user: DbUser) -> Result<()>;

    /// Updates an existing user in the store.
    ///
    /// The user is identified by their ID, and the provided `DbUser` struct
    /// contains the updated information.
    async fn update_user(&self, user: DbUser) -> Result<()>;

    /// Deletes a user from the store by their ID.
    async fn delete_user(&self, id: Ulid) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_created_at() {
        let expected_date = chrono::DateTime::parse_from_rfc3339("2026-06-26T08:36:00Z")
            .expect("Failed to parse expected date")
            .with_timezone(&chrono::Utc);

        let id = Ulid::from_datetime(expected_date.into());

        let user = DbUser {
            id,
            username: "testuser".to_string(),
            password_hash: "hashedpassword".to_string(),
            email: "testuser@example.com".to_string(),
        };

        let date = user.created_at();
        assert_eq!(date, expected_date);
    }
}
