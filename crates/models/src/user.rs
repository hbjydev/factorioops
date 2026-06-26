use chrono::DateTime;
use ulid::Ulid;

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
