use super::{
    constants, extensions::Extensions, file::FileAttrs, seq_iter::SeqIter, visitor::impl_visitor,
    HandleOwned,
};

use serde::de::{Deserializer, Error, Unexpected};
use serde::Deserialize;
use ssh_format::from_bytes;

use vec_strings::Strings;

#[derive(Debug, Clone)]
pub struct ServerVersion {
    pub version: u32,
    pub extensions: Extensions,
}
impl ServerVersion {
    /// * `bytes` - should not include the initial 4-byte which server
    ///   as the length of the whole packet.
    pub fn deserialize(bytes: &[u8]) -> ssh_format::Result<Self> {
        let (version, mut bytes) = from_bytes(bytes)?;

        let mut strings = Strings::new();
        while !bytes.is_empty() {
            let (string, bytes_left) = from_bytes(bytes)?;
            strings.push(string);

            bytes = bytes_left;
        }

        if let Some(extensions) = Extensions::new(strings) {
            Ok(Self {
                version,
                extensions,
            })
        } else {
            Err(ssh_format::Error::Eof)
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResponseInner {
    Status {
        status_code: StatusCode,

        err_msg: ErrMsg,
    },

    Handle(HandleOwned),

    /// The remaining bytes returned by ssh_format::from_bytes is the data
    /// of the packet.
    Data,

    Name(Box<[NameEntry]>),

    Attrs(FileAttrs),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub response_id: u32,
    pub response_inner: ResponseInner,
}

impl Response {
    /// * `packet_len` - total length of the packet, MUST NOT include the packet_type.
    ///
    /// Return Some(header_len) where header_len does not include
    /// the packet_type.
    /// Length of the body equals to packet_len - header_len.
    ///
    /// Return None if packet_type is invalid
    pub fn len_of_header(packet_len: usize, packet_type: u8) -> Option<usize> {
        use constants::*;

        match packet_type {
            SSH_FXP_STATUS | SSH_FXP_HANDLE | SSH_FXP_NAME | SSH_FXP_ATTRS => Some(packet_len),

            SSH_FXP_DATA => Some(4),

            _ => None,
        }
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

            SSH_FXP_DATA => Data,

            SSH_FXP_NAME => {
                let len: u32 = iter.get_next()?;
                let len = len as usize;
                let mut entries = Vec::<NameEntry>::with_capacity(len);

                for _ in 0..len {
                    entries.push(iter.get_next()?);
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
    /// Indicates end-of-file condition.
    ///
    /// For RequestInner::Read it means that no more data is available in the file,
    /// and for RequestInner::Readdir it indicates that no more files are contained
    /// in the directory.
    Eof,

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
    BadMessage,

    /// Indicates that an attempt was made to perform an operation which
    /// is not supported for the server.
    OpUnsupported,
}

#[derive(Debug, Copy, Clone)]
pub enum StatusCode {
    Success,
    Failure(ErrorCode),
}
impl<'de> Deserialize<'de> for StatusCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use constants::*;
        use ErrorCode::*;

        let discriminant = <u32 as Deserialize>::deserialize(deserializer)?;

        match discriminant {
            SSH_FX_OK => Ok(StatusCode::Success),
            SSH_FX_EOF => Ok(StatusCode::Failure(Eof)),
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

#[derive(Debug, Clone, Deserialize)]
pub struct ErrMsg {
    /// ISO-10646 UTF-8 [RFC-2279]
    err_msg: Box<str>,

    /// [RFC-1766]
    ///
    /// This tag can be parsed by
    /// [pyfisch/rust-language-tags](https://github.com/pyfisch/rust-language-tags)
    /// according to
    /// [this issue](https://github.com/pyfisch/rust-language-tags/issues/39).
    language_tag: Box<str>,
}

/// Entry in ResponseInner::Name
#[derive(Debug, Deserialize, Clone)]
pub struct NameEntry {
    pub filename: Box<str>,

    /// The format of the `longname' field is unspecified by this protocol.
    ///
    /// It MUST be suitable for use in the output of a directory listing
    /// command (in fact, the recommended operation for a directory listing
    /// command is to simply display this data).
    ///
    /// However, clients SHOULD NOT attempt to parse the longname field for file
    /// attributes, they SHOULD use the attrs field instead.
    ///
    /// The recommended format for the longname field is as follows:
    ///
    /// -rwxr-xr-x   1 mjos     staff      348911 Mar 25 14:29 t-filexfer
    /// 1234567890 123 12345678 12345678 12345678 123456789012
    pub longname: Box<str>,
    pub attrs: FileAttrs,
}
