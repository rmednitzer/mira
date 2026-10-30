//! Stable collection failures. These codes describe acquisition, never health.
use std::{fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    Timeout,
    LimitExceeded,
    MalformedData,
    PermissionDenied,
    NotFound,
    BackendFailed,
    IoFailure,
}

impl FailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::LimitExceeded => "limit_exceeded",
            Self::MalformedData => "malformed_data",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::BackendFailed => "backend_failed",
            Self::IoFailure => "io_failure",
        }
    }

    pub(crate) fn from_error(error: &io::Error) -> Self {
        if let Some(reason) = error.get_ref().and_then(|inner| inner.downcast_ref::<Self>()) {
            return *reason;
        }
        match error.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => Self::MalformedData,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NotFound => Self::NotFound,
            _ => Self::IoFailure,
        }
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl std::error::Error for FailureReason {}

pub(crate) fn limit_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, FailureReason::LimitExceeded)
}

pub(crate) fn backend_failed() -> io::Error {
    io::Error::other(FailureReason::BackendFailed)
}
