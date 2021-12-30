use super::file_attrs::{FileAttrs, FileAttrsBox};
use super::{constants, seq_iter::SeqIter, visitor::impl_visitor, HandleOwned};

use core::fmt;
use std::path::Path;
use std::str::from_utf8;

use serde::de::{Deserializer, Error, Unexpected};
use serde::Deserialize;

use vec_strings::TwoStrs;

/// The extension that the sftp-server supports.
#[derive(Debug, Default, Clone, Copy)]
pub struct Extensions {
    pub posix_rename: bool,
    pub statvfs: bool,
    pub fstatvfs: bool,
    pub hardlink: bool,
    pub fsync: bool,
    pub lsetstat: bool,
    pub limits: bool,
    pub expand_path: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ServerVersion {
    pub version: u32,
    pub extensions: Extensions,
}
impl ServerVersion {
    /// * `bytes` - should not include the initial 4-byte which server
    ///   as the length of the whole packet.
    pub fn deserialize(bytes: &[u8]) -> ssh_format::Result<Self> {
        macro_rules! ok_or_continue {
            ($res:expr) => {
                if let Ok(val) = $res {
                    val
                } else {
                    continue;
                }
            };
        }

        let mut de = ssh_format::Deserializer::from_bytes(bytes);

        let packet_type = u8::deserialize(&mut de)?;
        if packet_type != constants::SSH_FXP_VERSION {
            return Err(ssh_format::Error::custom("Unexpected response"));
        };

        let version = u32::deserialize(&mut de)?;

        let mut extensions = Extensions::default();
        while !de.into_inner().is_empty() {
            // sftp v3 does not specify the encoding of extension names and revisions.
            //
            // Read both name and revision before continue parsing them
            // so that if the current iteration is skipped by 'continue',
            // the next iteration can continue read in extensions without error.
            let name = <&[u8]>::deserialize(&mut de)?;
            let revision = <&[u8]>::deserialize(&mut de)?;

            let name = ok_or_continue!(from_utf8(name));
            let revision = ok_or_continue!(from_utf8(revision));
            let revision: u64 = ok_or_continue!(revision.parse());

            match (name, revision) {
                constants::EXT_NAME_POSIX_RENAME => {
                    extensions.posix_rename = true;
                }
                constants::EXT_NAME_STATVFS => {
                    extensions.statvfs = true;
                }
                constants::EXT_NAME_FSTATVFS => {
                    extensions.fstatvfs = true;
                }
                constants::EXT_NAME_HARDLINK => {
                    extensions.hardlink = true;
                }
                constants::EXT_NAME_FSYNC => {
                    extensions.fsync = true;
                }
                constants::EXT_NAME_LSETSTAT => {
                    extensions.lsetstat = true;
                }
                constants::EXT_NAME_LIMITS => {
                    extensions.limits = true;
                }
                constants::EXT_NAME_EXPAND_PATH => {
                    extensions.expand_path = true;
                }

                _ => (),
            }
        }

        Ok(Self {
            version,
            extensions,
        })
    }
}

/// Payload of extended reply response when `ResponseInner::Limits`
/// is sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
pub struct Limits {
    packet_len: u64,
    read_len: u64,
    write_len: u64,
    open_handles: u64,
}

#[derive(Debug)]
pub enum ResponseInner {
    Status {
        status_code: StatusCode,

        err_msg: ErrMsg,
    },

    Handle(HandleOwned),

    Name(Box<[NameEntry]>),

    Attrs(FileAttrsBox),
}

#[derive(Debug)]
pub struct Response {
    pub response_id: u32,
    pub response_inner: ResponseInner,
}

impl Response {
    /// Return true if the response is a data response.
    pub fn is_data(packet_type: u8) -> bool {
        packet_type == constants::SSH_FXP_DATA
    }

    /// Return true if the response is a extended reply response.
    pub fn is_extended_reply(packet_type: u8) -> bool {
        packet_type == constants::SSH_FXP_EXTENDED_REPLY
    }
}

impl_visitor!(
    Response,
    ResponseVisitor,
    "Expects a u8 type and payload",
    seq,
    {
        use constants::*;
        use ResponseInner::*;

        let mut iter = SeqIter::new(seq);

        let discriminant: u8 = iter.get_next()?;
        let response_id: u32 = iter.get_next()?;

        let response_inner = match discriminant {
            SSH_FXP_STATUS => Status {
                status_code: iter.get_next()?,
                err_msg: iter.get_next()?,
            },

            SSH_FXP_HANDLE => Handle(iter.get_next()?),

            SSH_FXP_NAME => {
                let len: u32 = iter.get_next()?;
                let len = len as usize;
                let mut entries = Vec::<NameEntry>::with_capacity(len);

                for _ in 0..len {
                    let filename: Box<Path> = iter.get_next()?;
                    let _longname: &[u8] = iter.get_next()?;
                    let attrs: FileAttrs = iter.get_next()?;

                    entries.push(NameEntry { filename, attrs });
                }

                Name(entries.into_boxed_slice())
            }

            SSH_FXP_ATTRS => Attrs(iter.get_next()?),

            _ => {
                return Err(Error::invalid_value(
                    Unexpected::Unsigned(discriminant as u64),
                    &"Invalid packet type",
                ))
            }
        };

        Ok(Response {
            response_id,
            response_inner,
        })
    }
);

#[derive(Debug, Copy, Clone)]
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

#[derive(Debug, Copy, Clone)]
pub enum StatusCode {
    Success,
    Failure(ErrorCode),

    /// Indicates end-of-file condition.
    ///
    /// For RequestInner::Read it means that no more data is available in the file,
    /// and for RequestInner::Readdir it indicates that no more files are contained
    /// in the directory.
    Eof,
}
impl<'de> Deserialize<'de> for StatusCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use constants::*;
        use ErrorCode::*;

        let discriminant = <u32 as Deserialize>::deserialize(deserializer)?;

        match discriminant {
            SSH_FX_OK => Ok(StatusCode::Success),
            SSH_FX_EOF => Ok(StatusCode::Eof),
            SSH_FX_NO_SUCH_FILE => Ok(StatusCode::Failure(NoSuchFile)),
            SSH_FX_PERMISSION_DENIED => Ok(StatusCode::Failure(PermDenied)),
            SSH_FX_FAILURE => Ok(StatusCode::Failure(Failure)),
            SSH_FX_BAD_MESSAGE => Ok(StatusCode::Failure(BadMessage)),
            SSH_FX_OP_UNSUPPORTED => Ok(StatusCode::Failure(OpUnsupported)),

            SSH_FX_NO_CONNECTION | SSH_FX_CONNECTION_LOST => Err(Error::invalid_value(
                Unexpected::Unsigned(discriminant as u64),
                &"Server MUST NOT return SSH_FX_NO_CONNECTION or SSH_FX_CONNECTION_LOST \
                for they are pseudo-error that can only be generated locally.",
            )),

            _ => Err(Error::invalid_value(
                Unexpected::Unsigned(discriminant as u64),
                &"Invalid status code",
            )),
        }
    }
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

/// Entry in ResponseInner::Name
#[derive(Debug, Clone)]
pub struct NameEntry {
    pub filename: Box<Path>,

    pub attrs: FileAttrs,
}
