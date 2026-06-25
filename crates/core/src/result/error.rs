#[derive(Debug, thiserror::Error)]
pub enum FactorioopsError {
    #[error("Unexpected error: {0}")]
    Other(#[from] anyhow::Error)
}
