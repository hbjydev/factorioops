#[derive(Debug, thiserror::Error)]
pub enum FactorioopsError {
    #[error("Security error: {0}")]
    SecurityError(String),

    #[error("Unexpected error: {0}")]
    Other(#[from] anyhow::Error),
}
