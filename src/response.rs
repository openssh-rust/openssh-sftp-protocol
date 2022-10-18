#![forbid(unsafe_code)]

use super::{
    file_attrs::FileAttrs,
    {constants, seq_iter::SeqIter, visitor::impl_visitor, HandleOwned},
};

use std::{borrow::Cow, iter::FusedIterator, path::Path, str::from_utf8};

use bitflags::bitflags;
use openssh_sftp_protocol_error::{ErrMsg, ErrorCode};
use serde::{
    de::{Deserializer, Error, Unexpected},
    Deserialize,
};

bitflags! {
    /// The extension that the sftp-server supports.
    #[derive(Default)]
    pub struct Extensions: u16 {
        const POSIX_RENAME = 1 << 0;
        const STATVFS = 1 << 1;
        const FSTATVFS= 1<< 2;
        const HARDLINK= 1<< 3;
        const FSYNC= 1<< 4;
        const LSETSTAT= 1<< 5;
        const LIMITS= 1<< 6;
        const EXPAND_PATH= 1<< 7;
        const COPY_DATA= 1<< 8;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServerVersion {
    pub version: u32,
    pub extensions: Extensions,
}
impl ServerVersion {
    /// * `bytes` - should not include the initial 4-byte which server
    ///   as the length of the whole packet.
    pub fn deserialize<'de, It>(
        de: &mut ssh_format::Deserializer<'de, It>,
    ) -> ssh_format::Result<Self>
    where
        It: FusedIterator + Iterator<Item = &'de [u8]>,
    {
        macro_rules! ok_or_continue {
            ($res:expr) => {
                if let Ok(val) = $res {
                    val
                } else {
                    continue;
                }
            };
        }

        let packet_type = u8::deserialize(&mut *de)?;
        if packet_type != constants::SSH_FXP_VERSION {
            return Err(ssh_format::Error::custom("Unexpected response"));
        }

        let version = u32::deserialize(&mut *de)?;

        let mut extensions = Extensions::default();

        while de.has_remaining_data() {
            // sftp v3 does not specify the encoding of extension names and revisions.
            //
            // Read both name and revision before continue parsing them
            // so that if the current iteration is skipped by 'continue',
            // the next iteration can continue read in extensions without error.
            let name = Cow::<'_, [u8]>::deserialize(&mut *de)?;
            let revision = Cow::<'_, [u8]>::deserialize(&mut *de)?;

            let name = ok_or_continue!(from_utf8(&name));
            let revision = ok_or_continue!(from_utf8(&revision));
            let revision: u64 = ok_or_continue!(revision.parse());

            match (name, revision) {
                constants::EXT_NAME_POSIX_RENAME => {
                    extensions |= Extensions::POSIX_RENAME;
                }
                constants::EXT_NAME_STATVFS => {
                    extensions |= Extensions::STATVFS;
                }
                constants::EXT_NAME_FSTATVFS => {
                    extensions |= Extensions::FSTATVFS;
                }
                constants::EXT_NAME_HARDLINK => {
                    extensions |= Extensions::HARDLINK;
                }
                constants::EXT_NAME_FSYNC => {
                    extensions |= Extensions::FSYNC;
                }
                constants::EXT_NAME_LSETSTAT => {
                    extensions |= Extensions::LSETSTAT;
                }
                constants::EXT_NAME_LIMITS => {
                    extensions |= Extensions::LIMITS;
                }
                constants::EXT_NAME_EXPAND_PATH => {
                    extensions |= Extensions::EXPAND_PATH;
                }
                constants::EXT_NAME_COPY_DATA => {
                    extensions |= Extensions::COPY_DATA;
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

/// Payload of extended reply response when [`crate::request::RequestInner::Limits`]
/// is sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
pub struct Limits {
    pub packet_len: u64,
    pub read_len: u64,
    pub write_len: u64,
    pub open_handles: u64,
}

#[derive(Debug)]
pub enum ResponseInner {
    Status {
        status_code: StatusCode,

        err_msg: ErrMsg,
    },

    Handle(HandleOwned),

    Name(Box<[NameEntry]>),

    Attrs(FileAttrs),
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

            SSH_FXP_HANDLE => Handle(HandleOwned(iter.get_next()?)),

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

            _ => Ok(StatusCode::Failure(Unknown)),
        }
    }
}

/// Entry in [`ResponseInner::Name`]
#[derive(Debug, Clone)]
pub struct NameEntry {
    pub filename: Box<Path>,

    pub attrs: FileAttrs,
}
