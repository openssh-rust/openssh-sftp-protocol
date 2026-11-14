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
    #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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

            let optional_extension_pair = (|| {
                let name = from_utf8(&name).ok()?;
                let revision = from_utf8(&revision).ok()?;
                let revision: u64 = revision.parse().ok()?;

                Some((name, revision))
            })();

            let extension_pair = if let Some(extension_pair) = optional_extension_pair {
                extension_pair
            } else {
                continue;
            };

            match extension_pair {
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

/// Payload of extended reply response when [`crate::request::RequestInner::Statvfs`]
/// or [`crate::request::RequestInner::Fstatvfs`] is sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
pub struct Statvfs {
    /// File system block size
    pub bsize: u64,
    /// Fundamental file system block size
    pub frsize: u64,
    /// Number of blocks (unit `frsize`)
    pub blocks: u64,
    /// Free blocks in file system
    pub bfree: u64,
    /// Free blocks for non-root
    pub bavail: u64,
    /// Total file inodes
    pub files: u64,
    /// Free file inodes
    pub ffree: u64,
    /// Free file inodes for non-root
    pub favail: u64,
    /// File system id
    pub fsid: u64,
    /// Bit mask of [`constants::SSH_FXE_STATVFS_ST_RDONLY`] and
    /// [`constants::SSH_FXE_STATVFS_ST_NOSUID`]
    pub flag: u64,
    /// Maximum filename length
    pub namemax: u64,
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
                    let Filename(filename) = iter.get_next()?;
                    let longname: &[u8] = iter.get_next()?;
                    let attrs: FileAttrs = iter.get_next()?;

                    entries.push(NameEntry {
                        filename,
                        longname: longname.into(),
                        attrs,
                    });
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

struct Filename(Box<Path>);

impl<'de> Deserialize<'de> for Filename {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_filename(deserializer).map(Filename)
    }
}

fn deserialize_filename<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Box<Path>, D::Error> {
    #[cfg(not(unix))]
    {
        Box::<Path>::deserialize(deserializer)
    }

    #[cfg(unix)]
    {
        use std::{
            ffi::{OsStr, OsString},
            fmt,
            os::unix::ffi::{OsStrExt, OsStringExt},
            path::PathBuf,
        };

        struct FilenameVisitor;

        impl<'de> serde::de::Visitor<'de> for FilenameVisitor {
            type Value = Box<Path>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a filename string")
            }

            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Ok(Path::new(OsStr::from_bytes(bytes)).into())
            }

            fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                Ok(PathBuf::from(OsString::from_vec(bytes)).into_boxed_path())
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                self.visit_bytes(value.as_bytes())
            }

            fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
                self.visit_byte_buf(value.into_bytes())
            }
        }

        // SFTP v3 filenames are SSH strings, not necessarily UTF-8 text.
        deserializer.deserialize_bytes(FilenameVisitor)
    }
}

/// Entry in [`ResponseInner::Name`]
#[derive(Debug, Deserialize, Clone)]
pub struct NameEntry {
    #[serde(deserialize_with = "deserialize_filename")]
    pub filename: Box<Path>,
    pub longname: Box<[u8]>,
    pub attrs: FileAttrs,
}

#[cfg(test)]
mod tests {
    use super::{NameEntry, Statvfs};
    use std::path::Path;

    #[cfg(unix)]
    use {super::Response, super::ResponseInner, serde::Deserialize, std::os::unix::ffi::OsStrExt};

    #[cfg(unix)]
    fn name_entry_bytes(filename: &[u8]) -> Vec<u8> {
        let mut bytes = (filename.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(filename);
        // Raw longname, then attributes containing size = 123.
        bytes.extend_from_slice(b"\0\0\0\x03\xff -\0\0\0\x01\0\0\0\0\0\0\0\x7b");
        bytes
    }

    #[cfg(unix)]
    #[test]
    fn name_response_preserves_raw_bytes() {
        let names: &[&[u8]] = &[b"raw-\xff\xfe", "é-雪".as_bytes()];
        let mut bytes = b"\x68\0\0\0\x11\0\0\0\x02".to_vec();
        for name in names {
            bytes.extend_from_slice(&name_entry_bytes(name));
        }
        bytes.push(0xaa);
        let (response, rest) = ssh_format::from_bytes::<Response>(&bytes).unwrap();
        assert_eq!(response.response_id, 17);
        assert_eq!(rest, &[0xaa]);
        let entries = match response.response_inner {
            ResponseInner::Name(entries) => entries,
            other => panic!("expected NAME, got {:?}", other),
        };
        assert_eq!(entries.len(), names.len());
        for (entry, name) in entries.iter().zip(names) {
            assert_eq!(entry.filename.as_os_str().as_bytes(), *name);
            assert_eq!(&*entry.longname, b"\xff -");
            assert_eq!(entry.attrs.get_size(), Some(123));
        }
    }

    #[cfg(unix)]
    #[test]
    fn name_entry_preserves_contiguous_and_chunked_bytes() {
        let bytes = name_entry_bytes(b"raw-\xff\xfe");
        for chunk_size in [bytes.len(), 5] {
            let mut deserializer = ssh_format::Deserializer::new(bytes.chunks(chunk_size));
            let entry = NameEntry::deserialize(&mut deserializer).unwrap();
            assert_eq!(entry.filename.as_os_str().as_bytes(), b"raw-\xff\xfe");
            assert_eq!(&*entry.longname, b"\xff -");
            assert_eq!(entry.attrs.get_size(), Some(123));
            assert!(!deserializer.has_remaining_data());
        }
    }

    #[test]
    fn name_entry_utf8_json() {
        let entry: NameEntry =
            serde_json::from_str(r#"{"filename":"é-雪","longname":[255,32,45],"attrs":[0]}"#)
                .unwrap();
        assert_eq!(&*entry.filename, Path::new("é-雪"));
        assert_eq!(&*entry.longname, b"\xff -");
        assert_eq!(entry.attrs.get_size(), None);
    }

    #[test]
    fn test_deserialize_statvfs() {
        let bytes: Vec<u8> = (1..=11u64).flat_map(u64::to_be_bytes).collect();
        let (statvfs, rest) = ssh_format::from_bytes::<Statvfs>(&bytes).unwrap();

        assert!(rest.is_empty());
        assert_eq!(
            statvfs,
            Statvfs {
                bsize: 1,
                frsize: 2,
                blocks: 3,
                bfree: 4,
                bavail: 5,
                files: 6,
                ffree: 7,
                favail: 8,
                fsid: 9,
                flag: 10,
                namemax: 11,
            }
        );
    }
}
