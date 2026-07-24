mod dns;
mod fetch;
mod target;

pub(crate) use fetch::{build_client, fetch_page, DEFAULT_MAX_BODY_BYTES};
pub use target::{is_public_ip, normalize_target};

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid target.")]
    InvalidTarget,
    #[error("Blocked target.")]
    BlockedTarget,
    #[error("HTTP client failed.")]
    Client,
    #[error("Request failed: {0}")]
    Request(String),
    #[error("Unexpected HTTP status: {0}.")]
    HttpStatus(u16),
}
