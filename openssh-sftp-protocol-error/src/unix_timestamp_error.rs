use std::{num::TryFromIntError, time::SystemTimeError};

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum UnixTimeStampError {
    /// TimeStamp is earlier than 1970-01-01 00:00:00 UTC.
    #[error("TimeStamp is earlier than 1970-01-01 00:00:00 UTC.")]
    TooEarly(#[from] SystemTimeError),

    /// TimeStamp is too large to be represented using u32 in seconds.
    #[error("TimeStamp is too large to be represented using u32 in seconds.")]
    TooLarge(#[from] TryFromIntError),
}
