// src/domain//errors.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Malformed domain name: {0}")]
    InvalidDomain(String),
    #[error("Network timeout while scanning endpoint: {0}")]
    Timeout(String),
    #[error("Failed to resolve DNS or establish connection: {0}")]
    ConnectionFailed(String),
    #[error("Target returned a non-success HTTP status: {0}")]
    BadStatus(u16),
    #[error("Network interface configuration failed: {0}")]
    NetworkConfigurationError(String),
    #[error("QUIC HTTP/3 connection failed (WAF Trap suspected): {0}")]
    QuicConnectionFailed(String),
}
