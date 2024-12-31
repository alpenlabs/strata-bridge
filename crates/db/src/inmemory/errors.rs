use thiserror::Error;

#[derive(Debug, Error)]
pub enum InMemoryError {
    #[error("could not find entry")]
    NotFound,
}
