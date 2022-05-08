#![forbid(unsafe_code)]

use super::{constants, file_attrs::FileAttrs, open_options::OpenOptions, Handle};

use std::borrow::Cow;
use std::path::Path;

use serde::{Serialize, Serializer};
use ssh_format::SerBacker;

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

            Remove(filename) => {
                (constants::SSH_FXP_REMOVE, request_id, filename).serialize(serializer)
            }

            Rename { oldpath, newpath } => {
                (constants::SSH_FXP_RENAME, request_id, oldpath, newpath).serialize(serializer)
            }

            Mkdir { path, attrs } => {
                (constants::SSH_FXP_MKDIR, request_id, path, attrs).serialize(serializer)
            }

            Rmdir(path) => (constants::SSH_FXP_RMDIR, request_id, path).serialize(serializer),

            Opendir(path) => (constants::SSH_FXP_OPENDIR, request_id, path).serialize(serializer),

            Readdir(handle) => {
                (constants::SSH_FXP_READDIR, request_id, handle).serialize(serializer)
            }

            Stat(path) => (constants::SSH_FXP_STAT, request_id, path).serialize(serializer),

            Lstat(path) => (constants::SSH_FXP_LSTAT, request_id, path).serialize(serializer),

            Fstat(handle) => (constants::SSH_FXP_FSTAT, request_id, handle).serialize(serializer),

            Setstat { path, attrs } => {
                (constants::SSH_FXP_SETSTAT, request_id, path, attrs).serialize(serializer)
            }

            Fsetstat { handle, attrs } => {
                (constants::SSH_FXP_FSETSTAT, request_id, handle, attrs).serialize(serializer)
            }

            Readlink(path) => (constants::SSH_FXP_READLINK, request_id, path).serialize(serializer),

            Symlink {
                linkpath,
                targetpath,
            } => {
                (constants::SSH_FXP_SYMLINK, request_id, targetpath, linkpath).serialize(serializer)
            }

            Realpath(path) => (constants::SSH_FXP_REALPATH, request_id, path).serialize(serializer),

            Limits => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_LIMITS.0,
            )
                .serialize(serializer),

            ExpandPath(path) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_EXPAND_PATH.0,
                path,
            )
                .serialize(serializer),

            Lsetstat(path, attrs) => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_LSETSTAT.0,
                path,
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
                oldpath,
                newpath,
            )
                .serialize(serializer),

            PosixRename { oldpath, newpath } => (
                constants::SSH_FXP_EXTENDED,
                request_id,
                constants::EXT_NAME_POSIX_RENAME.0,
                oldpath,
                newpath,
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
    pub fn serialize_write_request<'a, Container: SerBacker>(
        serializer: &'a mut ssh_format::Serializer<Container>,
        request_id: u32,
        handle: Cow<'_, Handle>,
        offset: u64,
        data_len: u32,
    ) -> ssh_format::Result<&'a mut Container> {
        serializer.reset();
        (
            constants::SSH_FXP_WRITE,
            request_id,
            handle,
            offset,
            data_len,
        )
            .serialize(&mut *serializer)?;

        serializer.get_output_with_data(data_len)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenFileRequest<'a> {
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
