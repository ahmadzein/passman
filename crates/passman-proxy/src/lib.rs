pub mod http;
pub mod sanitizer;
pub mod smtp;
pub mod sql;
pub mod ssh;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),
}

/// Install sqlx any-pool drivers. Call once at startup.
pub fn install_sql_drivers() {
    // sqlx 0.8 uses AnyPool::connect which auto-discovers drivers
    // if the feature flags are enabled. No explicit install needed
    // for the `any` feature with driver features enabled.
}
