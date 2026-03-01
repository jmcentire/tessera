use thiserror::Error;

#[derive(Debug, Error)]
pub enum TesseraError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("chain integrity violation: {0}")]
    ChainIntegrity(String),

    #[error("schema violation: {0}")]
    SchemaViolation(String),

    #[error("guard failed: {0}")]
    GuardFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("unknown mutation type: {0}")]
    UnknownMutation(String),

    #[error("unknown field: {0}")]
    UnknownField(String),

    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("invalid document: {0}")]
    InvalidDocument(String),

    #[error("code execution required: mutation '{0}' has a validator but no runtime provided")]
    CodeExecutionRequired(String),

    #[error("code execution not authorized: {0}")]
    CodeNotAuthorized(String),

    #[error("code execution failed: {0}")]
    CodeExecutionFailed(String),
}
