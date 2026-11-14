#![forbid(unsafe_code)]

use super::{constants, file_attrs::FileAttrs, open_options::OpenOptions, Handle};

use std::{borrow::Cow, path::Path};

use serde::{Serialize, Serializer};
use ssh_format::SerOutput;

fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        // SFTP filenames need not be UTF-8; retain string serialization when possible.
        match path.to_str() {
            Some(path) => serializer.serialize_str(path),
            None => serializer.serialize_bytes(path.as_os_str().as_bytes()),
        }
    }
    #[cfg(not(unix))]
    path.serialize(serializer)
}

struct BorrowedPath<'a>(&'a Path);

impl Serialize for BorrowedPath<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_path(self.0, serializer)
    }
}

/// Response with `Response::Version`.
pub struct Hello {
    pub version: u32,
}

impl Serialize for Hello {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (constants::SSH_FXP_INIT, self.version).serialize(serializer)
    }
}

#[derive(Debug)]
pub enum RequestInner<'a> {
    /// The response to this message will be either
    /// [`crate::response::ResponseInner::Handle`] (if the operation is successful) or
    /// [`crate::response::ResponseInner::Status`]
    /// (if the operation fails).
    Open(OpenFileRequest<'a>),

    /// Response will be [`crate::response::ResponseInner::Status`].
    Close(Cow<'a, Handle>),

    /// In response to this request, the server will read as many bytes as it
    /// can from the file (up to `len'), and return them in a ResponseInner::Data
    /// message.
    ///
    /// If an error occurs or EOF is encountered before reading any
    /// data, the server will respond with [`crate::response::ResponseInner::Status`].
    ///
    /// For normal disk files, it is guaranteed that this will read the specified
    /// number of bytes, or up to end of file.
    ///
    /// For e.g. device files this may return fewer bytes than requested.
    Read {
        handle: Cow<'a, Handle>,
        offset: u64,
        len: u32,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Remove(Cow<'a, Path>),

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Rename {
        oldpath: Cow<'a, Path>,
        newpath: Cow<'a, Path>,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Mkdir {
        path: Cow<'a, Path>,
        attrs: FileAttrs,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Rmdir(Cow<'a, Path>),

    /// Responds with a [`crate::response::ResponseInner::Handle`]
    /// or a [`crate::response::ResponseInner::Status`] message.
    Opendir(Cow<'a, Path>),

    /// Responds with a [`crate::response::ResponseInner::Name`] or
    /// a [`crate::response::ResponseInner::Status`] message
    Readdir(Cow<'a, Handle>),

    /// Responds with [`crate::response::ResponseInner::Attrs`] or
    /// [`crate::response::ResponseInner::Status`].
    Stat(Cow<'a, Path>),

    /// Responds with [`crate::response::ResponseInner::Attrs`] or
    /// [`crate::response::ResponseInner::Status`].
    ///
    /// Does not follow symlink.
    Lstat(Cow<'a, Path>),

    /// Responds with [`crate::response::ResponseInner::Attrs`] or
    /// [`crate::response::ResponseInner::Status`].
    Fstat(Cow<'a, Handle>),

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Setstat {
        path: Cow<'a, Path>,
        attrs: FileAttrs,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Fsetstat {
        handle: Cow<'a, Handle>,
        attrs: FileAttrs,
    },

    /// Responds with [`crate::response::ResponseInner::Name`] with a name and
    /// dummy attribute value or [`crate::response::ResponseInner::Status`] on error.
    Readlink(Cow<'a, Path>),

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    Symlink {
        linkpath: Cow<'a, Path>,
        targetpath: Cow<'a, Path>,
    },

    /// Responds with [`crate::response::ResponseInner::Name`] with a name and
    /// dummy attribute value or [`crate::response::ResponseInner::Status`] on error.
    Realpath(Cow<'a, Path>),

    /// Responds with extended reply, with payload [`crate::response::Limits`].
    ///
    /// Extension, only available if it is [`crate::response::Extensions::limits`]
    /// is returned by [`crate::response::ServerVersion`].
    Limits,

    /// Responds with extended reply, with payload [`crate::response::Statvfs`].
    ///
    /// Extension, only available if it is [`crate::response::Extensions::STATVFS`]
    /// is returned by [`crate::response::ServerVersion`].
    Statvfs(Cow<'a, Path>),

    /// Responds with extended reply, with payload [`crate::response::Statvfs`].
    ///
    /// Extension, only available if it is [`crate::response::Extensions::FSTATVFS`]
    /// is returned by [`crate::response::ServerVersion`].
    Fstatvfs(Cow<'a, Handle>),

    /// Same response as [`RequestInner::Realpath`].
    ///
    /// Extension, only available if it is [`crate::response::Extensions::expand_path`]
    /// is returned by [`crate::response::ServerVersion`].
    ///
    /// This supports canonicalisation of relative paths and those that need
    /// tilde-expansion, i.e. "~", "~/..." and "~user/...".
    ///
    /// These paths are expanded using shell-lilke rules and the resultant path
    /// is canonicalised similarly to [`RequestInner::Realpath`].
    ExpandPath(Cow<'a, Path>),

    /// Same response as [`RequestInner::Setstat`].
    ///
    /// Extension, only available if it is [`crate::response::Extensions::lsetstat`]
    /// is returned by [`crate::response::ServerVersion`].
    Lsetstat(Cow<'a, Path>, FileAttrs),

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// Extension, only available if it is [`crate::response::Extensions::fsync`]
    /// is returned by [`crate::response::ServerVersion`].
    Fsync(Cow<'a, Handle>),

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// Extension, only available if it is [`crate::response::Extensions::hardlink`]
    /// is returned by [`crate::response::ServerVersion`].
    HardLink {
        oldpath: Cow<'a, Path>,
        newpath: Cow<'a, Path>,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// Extension, only available if it is [`crate::response::Extensions::posix_rename`]
    /// is returned by [`crate::response::ServerVersion`].
    PosixRename {
        oldpath: Cow<'a, Path>,
        newpath: Cow<'a, Path>,
    },

    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// Extension, only available if it is [`crate::response::Extensions::posix_rename`]
    /// is returned by [`crate::response::ServerVersion`].
    ///
    /// For [openssh-portable], this is available from V_9_0_P1.
    ///
    /// The server MUST copy the data exactly as if the client had issued a
    /// series of [`RequestInner::Read`] requests on the `read_from_handle`
    /// starting at `read_from_offset` and totaling `read_data_length` bytes,
    /// and issued a series of [`RequestInner::Write`] packets on the
    /// `write_to_handle`, starting at the `write_from_offset`, and totaling
    /// the total number of bytes read by the [`RequestInner::Read`] packets.
    ///
    /// The server SHOULD allow `read_from_handle` and `write_to_handle` to
    /// be the same handle as long as the range of data is not overlapping.
    /// This allows data to efficiently be moved within a file.
    ///
    /// If `data_length` is `0`, this imples data should be read until EOF is
    /// encountered.
    ///
    /// There are no protocol restictions on this operation; however, the
    /// server MUST ensure that the user does not exceed quota, etc.  The
    /// server is, as always, free to complete this operation out of order if
    /// it is too large to complete immediately, or to refuse a request that
    /// is too large.
    ///
    /// [openssh-portable]: https://github.com/openssh/openssh-portable
    Cp {
        read_from_handle: Cow<'a, Handle>,
        read_from_offset: u64,
        read_data_length: u64,

        write_to_handle: Cow<'a, Handle>,
        write_to_offset: u64,
    },

    /// The write will extend the file if writing beyond the end of the file.
    ///
    /// It is legal to write way beyond the end of the file, the semantics
    /// are to write zeroes from the end of the file to the specified offset
    /// and then the data.
    ///
    /// On most operating systems, such writes do not allocate disk space but
    /// instead leave "holes" in the file.
    ///
    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// The Write also includes any amount of custom data and its size is
    /// included in the size of the entire packet sent.
    Write {
        handle: Cow<'a, Handle>,
        offset: u64,
        data: Cow<'a, [u8]>,
    },
}

#[derive(Debug)]
pub struct Request<'a> {
    pub request_id: u32,
    pub inner: RequestInner<'a>,
}
impl Serialize for Request<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use RequestInner::*;

        let request_id = self.request_id;

        match &self.inner {
            Open(params) => (constants::SSH_FXP_OPEN, request_id, params).serialize(serializer),
            Close(handle) => (constants::SSH_FXP_CLOSE, request_id, handle).serialize(serializer),
            Read {
                handle,
                offset,
                len,
            } => (constants::SSH_FXP_READ, request_id, handle, *offset, *len).serialize(serializer),

            Remove(filename) => (
                constants::SSH_FXP_REMOVE,
                request_id,
                BorrowedPath(filename),
            )
                .serialize(serializer),

            Rename { oldpath, newpath } => (
                constants::SSH_FXP_RENAME,
                request_id,
                BorrowedPath(oldpath),
                BorrowedPath(newpath),
            )
                .serialize(serializer),

            Mkdir { path, attrs } => (
                constants::SSH_FXP_MKDIR,
                request_id,
                BorrowedPath(path),
                attrs,
            )
                .serialize(serializer),

            Rmdir(path) => {
                (constants::SSH_FXP_RMDIR, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Opendir(path) => {
                (constants::SSH_FXP_OPENDIR, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Readdir(handle) => {
                (constants::SSH_FXP_READDIR, request_id, handle).serialize(serializer)
            }

            Stat(path) => {
                (constants::SSH_FXP_STAT, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Lstat(path) => {
                (constants::SSH_FXP_LSTAT, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Fstat(handle) => (constants::SSH_FXP_FSTAT, request_id, handle).serialize(serializer),

            Setstat { path, attrs } => (
                constants::SSH_FXP_SETSTAT,
                request_id,
                BorrowedPath(path),
                attrs,
            )
                .serialize(serializer),

            Fsetstat { handle, attrs } => {
                (constants::SSH_FXP_FSETSTAT, request_id, handle, attrs).serialize(serializer)
            }

            Readlink(path) => {
                (constants::SSH_FXP_READLINK, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Symlink {
                linkpath,
                targetpath,
            } => (
                constants::SSH_FXP_SYMLINK,
                request_id,
                BorrowedPath(targetpath),
                BorrowedPath(linkpath),
            )
                .serialize(serializer),

            Realpath(path) => {
                (constants::SSH_FXP_REALPATH, request_id, BorrowedPath(path)).serialize(serializer)
            }

            Limits => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_LIMITS.0,
            )
                .serialize(serializer),

            Statvfs(path) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_STATVFS.0,
                BorrowedPath(path),
            )
                .serialize(serializer),

            Fstatvfs(handle) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_FSTATVFS.0,
                handle,
            )
                .serialize(serializer),

            ExpandPath(path) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_EXPAND_PATH.0,
                BorrowedPath(path),
            )
                .serialize(serializer),

            Lsetstat(path, attrs) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_LSETSTAT.0,
                BorrowedPath(path),
                attrs,
            )
                .serialize(serializer),

            Fsync(handle) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_FSYNC.0,
                handle,
            )
                .serialize(serializer),

            HardLink { oldpath, newpath } => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_HARDLINK.0,
                BorrowedPath(oldpath),
                BorrowedPath(newpath),
            )
                .serialize(serializer),

            PosixRename { oldpath, newpath } => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_POSIX_RENAME.0,
                BorrowedPath(oldpath),
                BorrowedPath(newpath),
            )
                .serialize(serializer),

            Cp {
                read_from_handle,
                read_from_offset,
                read_data_length,
                write_to_handle,
                write_to_offset,
            } => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_COPY_DATA.0,
                read_from_handle,
                read_from_offset,
                read_data_length,
                write_to_handle,
                write_to_offset,
            )
                .serialize(serializer),

            Write {
                handle,
                offset,
                data,
            } => (constants::SSH_FXP_WRITE, request_id, handle, offset, data).serialize(serializer),
        }
    }
}
impl Request<'_> {
    /// The write will extend the file if writing beyond the end of the file.
    ///
    /// It is legal to write way beyond the end of the file, the semantics
    /// are to write zeroes from the end of the file to the specified offset
    /// and then the data.
    ///
    /// On most operating systems, such writes do not allocate disk space but
    /// instead leave "holes" in the file.
    ///
    /// Responds with a [`crate::response::ResponseInner::Status`] message.
    ///
    /// The Write also includes any amount of custom data and its size is
    /// included in the size of the entire packet sent.
    ///
    /// Return the serialized header (including the 4-byte size).
    ///
    ///  * `serializer` - must be empty
    pub fn serialize_write_request<Output: SerOutput>(
        serializer: &mut ssh_format::Serializer<Output>,
        request_id: u32,
        handle: Cow<'_, Handle>,
        offset: u64,
        data_len: u32,
    ) -> ssh_format::Result<[u8; 4]> {
        (
            constants::SSH_FXP_WRITE,
            request_id,
            handle,
            offset,
            data_len,
        )
            .serialize(&mut *serializer)?;

        serializer.create_header(data_len)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenFileRequest<'a> {
    #[serde(serialize_with = "serialize_path")]
    pub(crate) filename: Cow<'a, Path>,
    pub(crate) flags: u32,
    pub(crate) attrs: FileAttrs,
}

impl<'a> OpenFileRequest<'a> {
    /// Open file in read only mode
    pub const fn open(filename: Cow<'a, Path>) -> Self {
        OpenOptions::new().read(true).open(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::{Cow, FileAttrs, OpenFileRequest, Path, Request, RequestInner};
    use serde::Serialize;

    fn string(bytes: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(bytes);
    }

    fn packet(kind: u8, extension: &[u8], paths: &[&[u8]], tail: &[u8]) -> Vec<u8> {
        let mut body = vec![kind, 0, 0, 0, 17];
        if !extension.is_empty() {
            string(extension, &mut body);
        }
        for path in paths {
            string(path, &mut body);
        }
        body.extend_from_slice(tail);
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    fn attrs() -> FileAttrs {
        let mut attrs = FileAttrs::default();
        attrs.set_size(0x0102030405060708);
        attrs
    }

    const ATTRS: &[u8] = &[0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8];

    fn assert_single_paths(path: &Path, bytes: &[u8]) {
        use RequestInner::*;
        let path = Cow::Borrowed(path);
        let cases = [
            (
                "open",
                Open(OpenFileRequest::open(path.clone())),
                3,
                &b""[..],
                &b"\0\0\0\x01\0\0\0\0"[..],
            ),
            ("remove", Remove(path.clone()), 13, &b""[..], &b""[..]),
            (
                "mkdir",
                Mkdir {
                    path: path.clone(),
                    attrs: attrs(),
                },
                14,
                &b""[..],
                ATTRS,
            ),
            ("rmdir", Rmdir(path.clone()), 15, &b""[..], &b""[..]),
            ("opendir", Opendir(path.clone()), 11, &b""[..], &b""[..]),
            ("stat", Stat(path.clone()), 17, &b""[..], &b""[..]),
            ("lstat", Lstat(path.clone()), 7, &b""[..], &b""[..]),
            (
                "setstat",
                Setstat {
                    path: path.clone(),
                    attrs: attrs(),
                },
                9,
                &b""[..],
                ATTRS,
            ),
            ("readlink", Readlink(path.clone()), 19, &b""[..], &b""[..]),
            ("realpath", Realpath(path.clone()), 16, &b""[..], &b""[..]),
            (
                "statvfs",
                Statvfs(path.clone()),
                200,
                &b"statvfs@openssh.com"[..],
                &b""[..],
            ),
            (
                "expand-path",
                ExpandPath(path.clone()),
                200,
                &b"expand-path@openssh.com"[..],
                &b""[..],
            ),
            (
                "lsetstat",
                Lsetstat(path, attrs()),
                200,
                &b"lsetstat@openssh.com"[..],
                ATTRS,
            ),
        ];
        for (name, inner, kind, extension, tail) in cases {
            let request = Request {
                request_id: 17,
                inner,
            };
            assert_eq!(
                ssh_format::to_bytes(&request)
                    .unwrap_or_else(|error| panic!("{}: {:?}", name, error)),
                packet(kind, extension, &[bytes], tail),
                "{name}: {bytes:?}",
            );
        }
    }

    fn assert_two_paths(first: &Path, first_bytes: &[u8], second: &Path, second_bytes: &[u8]) {
        use RequestInner::*;
        let first = Cow::Borrowed(first);
        let second: Cow<'_, Path> = Cow::Owned(second.to_path_buf());
        let cases = [
            (
                "rename",
                Rename {
                    oldpath: first.clone(),
                    newpath: second.clone(),
                },
                18,
                &b""[..],
                false,
            ),
            (
                "symlink",
                Symlink {
                    linkpath: first.clone(),
                    targetpath: second.clone(),
                },
                20,
                &b""[..],
                true,
            ),
            (
                "hardlink",
                HardLink {
                    oldpath: first.clone(),
                    newpath: second.clone(),
                },
                200,
                &b"hardlink@openssh.com"[..],
                false,
            ),
            (
                "posix-rename",
                PosixRename {
                    oldpath: first,
                    newpath: second,
                },
                200,
                &b"posix-rename@openssh.com"[..],
                false,
            ),
        ];
        for (name, inner, kind, extension, target_first) in cases {
            let paths = if target_first {
                [second_bytes, first_bytes]
            } else {
                [first_bytes, second_bytes]
            };
            assert_eq!(
                ssh_format::to_bytes(&Request {
                    request_id: 17,
                    inner
                })
                .unwrap_or_else(|error| panic!("{}: {:?}", name, error)),
                packet(kind, extension, &paths, &[]),
                "{name}: {first_bytes:?}, {second_bytes:?}",
            );
        }
    }

    fn assert_open(path: &Path, bytes: &[u8]) {
        for filename in [Cow::Borrowed(path), Cow::Owned(path.to_path_buf())] {
            let open = OpenFileRequest::open(filename);
            let mut expected = Vec::new();
            string(bytes, &mut expected);
            expected.extend_from_slice(b"\0\0\0\x01\0\0\0\0");
            let mut serializer = ssh_format::Serializer::new(Vec::new());
            open.serialize(&mut serializer).unwrap();
            assert_eq!(serializer.output, expected);
            assert_eq!(
                ssh_format::to_bytes(&Request {
                    request_id: 17,
                    inner: RequestInner::Open(open)
                })
                .unwrap(),
                packet(3, &[], &[bytes], b"\0\0\0\x01\0\0\0\0"),
            );
        }
    }

    #[test]
    fn utf8_paths_keep_wire_and_json_compatibility() {
        for text in ["ascii", "quote'\"\\\n\x01-é-雪"] {
            let path = Path::new(text);
            assert_single_paths(path, text.as_bytes());
            assert_two_paths(path, text.as_bytes(), Path::new("other"), b"other");
            assert_open(path, text.as_bytes());
            let open = OpenFileRequest::open(Cow::Borrowed(path));
            assert_eq!(serde_json::to_value(&open).unwrap()["filename"], text);
            let request = Request {
                request_id: 17,
                inner: RequestInner::Stat(Cow::Borrowed(path)),
            };
            assert_eq!(
                serde_json::to_value(&request).unwrap(),
                serde_json::json!([17, 17, text])
            );
        }
    }

    #[test]
    fn utf8_embedded_nul_keeps_existing_serialization() {
        let text = "a\0b";
        let path = Path::new(text);
        assert_single_paths(path, b"ab");
        assert_two_paths(path, b"ab", Path::new("other"), b"other");
        assert_open(path, b"ab");
        let open = OpenFileRequest::open(Cow::Borrowed(path));
        assert_eq!(serde_json::to_value(&open).unwrap()["filename"], text);
    }

    #[cfg(unix)]
    #[test]
    fn outgoing_single_paths_preserve_unix_bytes() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let bytes = b"raw-\xff\xfe'\"\\\n\x01";
        assert_single_paths(Path::new(OsStr::from_bytes(bytes)), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn outgoing_two_paths_preserve_unix_bytes_in_both_positions() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let bytes = b"raw-\xff\xfe";
        let raw = Path::new(OsStr::from_bytes(bytes));
        let text = "other-'\"\\\n\x01-é-雪";
        assert_two_paths(raw, bytes, Path::new(text), text.as_bytes());
        assert_two_paths(Path::new(text), text.as_bytes(), raw, bytes);
    }

    #[cfg(unix)]
    #[test]
    fn standalone_open_preserves_borrowed_and_owned_unix_bytes() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let bytes = b"raw-\xff\xfe";
        assert_open(Path::new(OsStr::from_bytes(bytes)), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn decoded_name_can_address_an_outgoing_request() {
        use crate::response::{Response, ResponseInner};
        use std::os::unix::ffi::OsStrExt;
        let bytes = b"raw-\xff\xfe";
        let mut body = vec![104, 0, 0, 0, 17, 0, 0, 0, 1];
        string(bytes, &mut body);
        string(b"\xff -", &mut body);
        body.extend_from_slice(&[0, 0, 0, 0]);
        let (response, rest) = ssh_format::from_bytes::<Response>(&body).unwrap();
        assert!(rest.is_empty());
        assert_eq!(response.response_id, 17);
        let entries = match response.response_inner {
            ResponseInner::Name(entries) => entries,
            other => panic!("expected NAME, got {:?}", other),
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename.as_os_str().as_bytes(), bytes);
        assert_eq!(&*entries[0].longname, b"\xff -");
        let request = Request {
            request_id: 17,
            inner: RequestInner::Stat(Cow::Borrowed(&entries[0].filename)),
        };
        assert_eq!(
            ssh_format::to_bytes(&request).unwrap(),
            packet(17, &[], &[bytes], &[])
        );
    }
}
