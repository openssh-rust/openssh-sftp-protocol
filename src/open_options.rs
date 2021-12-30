use super::constants;
use super::file_attrs::FileAttrs;
use super::request::OpenFile;

use std::borrow::Cow;
use std::path::Path;

#[derive(Debug, Copy, Clone)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
}

impl OpenOptions {
    pub const fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
        }
    }

    pub const fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    pub const fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    pub const fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    pub const fn open(self, filename: Cow<'_, Path>) -> OpenFile<'_> {
        let mut flags: u32 = 0;

        if self.read {
            flags |= constants::SSH_FXF_READ;
        }

        if self.write || self.append {
            flags |= constants::SSH_FXF_WRITE;
        }

        if self.append {
            flags |= constants::SSH_FXF_APPEND;
        }

        OpenFile {
            filename,
            flags,
            attrs: FileAttrs::new(),
        }
    }

    pub const fn create(
        self,
        filename: Cow<'_, Path>,
        flags: CreateFlags,
        attrs: FileAttrs,
    ) -> OpenFile<'_> {
        let mut openfile = self.open(filename);
        openfile.flags |= flags as u32;
        openfile.attrs = attrs;
        openfile
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum CreateFlags {
    None = 0,

    /// Forces an existing file with the same name to be truncated to zero
    /// length when creating a file.
    Trunc = constants::SSH_FXF_TRUNC,

    /// Causes the request to fail if the named file already exists.
    Excl = constants::SSH_FXF_EXCL,
}
