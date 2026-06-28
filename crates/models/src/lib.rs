pub mod user;

/// Options for paginating results from the database.
#[derive(Debug)]
pub struct PaginationOptions {
    /// The maximum number of items to return in a single page. If not
    /// specified, defaults to 50.
    pub limit: Option<i64>,
}

impl Default for PaginationOptions {
    fn default() -> Self {
        Self { limit: Some(50) }
    }
}

pub trait Storage: Send + Sync + 'static + user::UserStore {}

impl<T> Storage for T where T: Send + Sync + 'static + user::UserStore {}
