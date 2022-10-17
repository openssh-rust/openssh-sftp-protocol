use std::fmt;

use serde::Deserialize;
use vec_strings::TwoStrs;

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum ErrorCode {
    /// is returned when a reference is made to a file which should exist
    /// but doesn't.
    NoSuchFile,

    /// Returned when the authenticated user does not have sufficient
    /// permissions to perform the operation.
    PermDenied,

    /// A generic catch-all error message.
    ///
    /// It should be returned if an error occurs for which there is no more
    /// specific error code defined.
    Failure,

    /// May be returned if a badly formatted packet or protocol
    /// incompatibility is detected.
    ///
    /// If the handle is opened read only, but write flag is required,
    /// then `BadMessage` might be returned, vice versa.
    BadMessage,

    /// Indicates that an attempt was made to perform an operation which
    /// is not supported for the server.
    OpUnsupported,
}

#[derive(Clone, Deserialize)]
pub struct ErrMsg(TwoStrs);

impl ErrMsg {
    /// Returns (err_message, language_tag).
    ///
    /// Language tag is defined according to specification [RFC-1766].
    ///
    /// It can be parsed by
    /// [pyfisch/rust-language-tags](https://github.com/pyfisch/rust-language-tags)
    /// according to
    /// [this issue](https://github.com/pyfisch/rust-language-tags/issues/39).
    pub fn get(&self) -> (&str, &str) {
        self.0.get()
    }
}

impl fmt::Display for ErrMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (err_msg, language_tag) = self.get();
        write!(
            f,
            "Err Message: {}, Language Tag: {}",
            err_msg, language_tag
        )
    }
}

impl fmt::Debug for ErrMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
