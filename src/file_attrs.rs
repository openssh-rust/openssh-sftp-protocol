#![forbid(unsafe_code)]

use super::{
    constants,
    {seq_iter::SeqIter, visitor::impl_visitor},
};

use std::{
    convert::TryInto,
    time::{Duration, SystemTime},
};

use bitflags::bitflags;
use num_derive::FromPrimitive;
use num_traits::cast::FromPrimitive;
use openssh_sftp_protocol_error::UnixTimeStampError;
use serde::{
    de::{Error, Unexpected},
    ser::{SerializeTuple, Serializer},
    Serialize,
};

/// bit mask for the file type bit field
const S_IFMT: u32 = 0o170000;

bitflags! {
    #[derive(Default)]
    struct FileAttrsFlags: u8 {
        const SIZE = 1 << 0;
        const ID = 1 << 1;
        const PERMISSIONS = 1 << 2;
        const TIME = 1 << 3;
        const EXTENSIONS = 1 << 4;
    }
}
impl Serialize for FileAttrsFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use constants::{
            SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_PERMISSIONS, SSH_FILEXFER_ATTR_SIZE,
            SSH_FILEXFER_ATTR_UIDGID,
        };

        let mut flags: u32 = 0;
        if self.intersects(FileAttrsFlags::SIZE) {
            flags |= SSH_FILEXFER_ATTR_SIZE;
        }
        if self.intersects(FileAttrsFlags::ID) {
            flags |= SSH_FILEXFER_ATTR_UIDGID;
        }
        if self.intersects(FileAttrsFlags::PERMISSIONS) {
            flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if self.intersects(FileAttrsFlags::TIME) {
            flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        }

        flags.serialize(serializer)
    }
}

impl<'de> crate::visitor::Deserialize<'de> for FileAttrsFlags {
    fn deserialize<D: crate::visitor::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use constants::{
            SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_EXTENDED, SSH_FILEXFER_ATTR_PERMISSIONS,
            SSH_FILEXFER_ATTR_SIZE, SSH_FILEXFER_ATTR_UIDGID,
        };

        let flags = u32::deserialize(deserializer)?;
        let has_attr = |attr_mask| -> bool { (flags & attr_mask) != 0 };

        let mut file_attrs_flags = FileAttrsFlags::empty();

        if has_attr(SSH_FILEXFER_ATTR_SIZE) {
            file_attrs_flags |= FileAttrsFlags::SIZE;
        }
        if has_attr(SSH_FILEXFER_ATTR_UIDGID) {
            file_attrs_flags |= FileAttrsFlags::ID;
        }
        if has_attr(SSH_FILEXFER_ATTR_PERMISSIONS) {
            file_attrs_flags |= FileAttrsFlags::PERMISSIONS;
        }
        if has_attr(SSH_FILEXFER_ATTR_ACMODTIME) {
            file_attrs_flags |= FileAttrsFlags::TIME;
        }
        if has_attr(SSH_FILEXFER_ATTR_EXTENDED) {
            file_attrs_flags |= FileAttrsFlags::EXTENSIONS;
        }

        Ok(file_attrs_flags)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Permissions: u32 {
        /// set-user-ID (set process effective user ID on execve(2))
        const SET_UID = 0o4000;

        /// set-group-ID
        ///
        ///  - set process effective group ID on execve(2)
        ///  - mandatory locking, as described in fcntl(2)
        ///  - take a new file's group from parent directory, as described in
        ///    chown(2) and mkdir(2)
        const SET_GID = 0o2000;

        /// sticky bit (restricted deletion flag, as described in unlink(2))
        const SET_VTX = 0o1000;

        /// read by owner
        const READ_BY_OWNER = 0o400;

        /// write by owner
        const WRITE_BY_OWNER = 0o200;

        /// execute file or search directory by owner
        const EXECUTE_BY_OWNER = 0o100;

        /// read by group
        const READ_BY_GROUP = 0o40;

        /// write by group
        const WRITE_BY_GROUP = 0o20;

        /// execute/search by group
        const EXECUTE_BY_GROUP = 0o10;

        /// read by others
        const READ_BY_OTHER = 0o4;

        /// write by others
        const WRITE_BY_OTHER = 0o2;

        /// execute/search by others
        const EXECUTE_BY_OTHER = 0o1;
    }
}

#[derive(Debug, Clone, Copy, FromPrimitive, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum FileType {
    Socket = 0o140000,
    Symlink = 0o120000,
    RegularFile = 0o100000,
    BlockDevice = 0o60000,
    Directory = 0o40000,
    CharacterDevice = 0o20000,
    FIFO = 0o10000,
}

/// Default value is 1970-01-01 00:00:00 UTC.
///
/// UnixTimeStamp stores number of seconds elapsed since 1970-01-01 00:00:00 UTC
/// as `u32`.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UnixTimeStamp(u32);

impl UnixTimeStamp {
    pub fn new(system_time: SystemTime) -> Result<Self, UnixTimeStampError> {
        let duration = system_time.duration_since(SystemTime::UNIX_EPOCH)?;
        let seconds: u32 = duration.as_secs().try_into()?;
        Ok(Self(seconds))
    }

    /// Return unix epoch, same as [`UnixTimeStamp::default`]
    pub const fn unix_epoch() -> Self {
        Self(0)
    }

    /// Return `None` if [`std::time::SystemTime`] cannot hold the timestamp.
    pub fn from_raw(elapsed: u32) -> Option<Self> {
        let this = Self(elapsed);

        let duration = this.as_duration();
        SystemTime::UNIX_EPOCH.checked_add(duration)?;

        Some(this)
    }

    pub fn into_raw(self) -> u32 {
        self.0
    }

    pub fn as_duration(self) -> Duration {
        Duration::from_secs(self.0 as u64)
    }

    pub fn as_system_time(self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.as_duration()
    }
}

impl_visitor!(
    UnixTimeStamp,
    UnixTimeStampVisitor,
    "Unix Timestamp",
    seq,
    {
        let mut iter = SeqIter::new(seq);
        let elapsed: u32 = iter.get_next()?;

        let timestamp = UnixTimeStamp::from_raw(elapsed).ok_or_else(|| {
            V::Error::invalid_value(
                Unexpected::Unsigned(elapsed as u64),
                &"Invalid UnixTimeStamp (seconds)",
            )
        })?;

        Ok(timestamp)
    }
);

#[derive(Debug, Default, Copy, Clone)]
pub struct FileAttrs {
    flags: FileAttrsFlags,

    /// present only if flag SSH_FILEXFER_ATTR_SIZE
    size: u64,

    /// present only if flag SSH_FILEXFER_ATTR_UIDGID
    uid: u32,
    gid: u32,

    /// present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
    st_mode: u32,

    /// present only if flag SSH_FILEXFER_ATTR_ACMODTIME
    atime: UnixTimeStamp,
    mtime: UnixTimeStamp,
}

impl PartialEq for FileAttrs {
    fn eq(&self, other: &Self) -> bool {
        self.get_size() == other.get_size()
            && self.get_id() == other.get_id()
            && self.get_permissions() == other.get_permissions()
            && self.get_filetype() == other.get_filetype()
            && self.get_time() == other.get_time()
    }
}

impl Eq for FileAttrs {}

impl FileAttrs {
    pub const fn new() -> Self {
        Self {
            flags: FileAttrsFlags::empty(),
            size: 0,

            uid: 0,
            gid: 0,

            st_mode: 0,

            atime: UnixTimeStamp::unix_epoch(),
            mtime: UnixTimeStamp::unix_epoch(),
        }
    }

    pub fn set_size(&mut self, size: u64) {
        self.flags |= FileAttrsFlags::SIZE;
        self.size = size;
    }

    pub fn set_id(&mut self, uid: u32, gid: u32) {
        self.flags |= FileAttrsFlags::ID;
        self.uid = uid;
        self.gid = gid;
    }

    pub fn set_permissions(&mut self, permissions: Permissions) {
        self.flags |= FileAttrsFlags::PERMISSIONS;
        let filetype = self.st_mode & S_IFMT;
        self.st_mode = filetype | permissions.bits();
    }

    pub fn set_time(&mut self, atime: UnixTimeStamp, mtime: UnixTimeStamp) {
        self.flags |= FileAttrsFlags::TIME;
        self.atime = atime;
        self.mtime = mtime;
    }

    fn has_attr(&self, flag: FileAttrsFlags) -> bool {
        self.flags.intersects(flag)
    }

    fn getter_impl<T>(&self, flag: FileAttrsFlags, f: impl FnOnce() -> T) -> Option<T> {
        if self.has_attr(flag) {
            Some(f())
        } else {
            None
        }
    }

    pub fn get_size(&self) -> Option<u64> {
        self.getter_impl(FileAttrsFlags::SIZE, || self.size)
    }

    /// Return uid and gid
    pub fn get_id(&self) -> Option<(u32, u32)> {
        self.getter_impl(FileAttrsFlags::ID, || (self.uid, self.gid))
    }

    pub fn get_permissions(&self) -> Option<Permissions> {
        self.getter_impl(FileAttrsFlags::PERMISSIONS, || {
            Permissions::from_bits_truncate(self.st_mode)
        })
    }

    /// filetype is only set by the sftp-server.
    pub fn get_filetype(&self) -> Option<FileType> {
        self.getter_impl(FileAttrsFlags::PERMISSIONS, || {
            let filetype = self.st_mode & S_IFMT;

            if filetype == 0 {
                None
            } else {
                Some(FileType::from_u32(filetype).unwrap())
            }
        })
        .flatten()
    }

    /// Return atime and mtime
    pub fn get_time(&self) -> Option<(UnixTimeStamp, UnixTimeStamp)> {
        self.getter_impl(FileAttrsFlags::TIME, || (self.atime, self.mtime))
    }
}

impl Serialize for FileAttrs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // dummy size since ssh_format doesn't care
        let mut tuple_serializer = serializer.serialize_tuple(1)?;

        tuple_serializer.serialize_element(&self.flags)?;

        if let Some(size) = self.get_size() {
            tuple_serializer.serialize_element(&size)?;
        }

        if let Some((uid, gid)) = self.get_id() {
            tuple_serializer.serialize_element(&uid)?;
            tuple_serializer.serialize_element(&gid)?;
        }

        if let Some(perm) = self.get_permissions() {
            tuple_serializer.serialize_element(&perm.bits())?;
        }

        if let Some((atime, mtime)) = self.get_time() {
            tuple_serializer.serialize_element(&atime.into_raw())?;
            tuple_serializer.serialize_element(&mtime.into_raw())?;
        }

        tuple_serializer.end()
    }
}

impl_visitor!(FileAttrs, FileAttrVisitor, "File attributes", seq, {
    let mut iter = SeqIter::new(seq);
    let mut attrs = FileAttrs {
        flags: iter.get_next()?,
        ..Default::default()
    };

    if attrs.has_attr(FileAttrsFlags::SIZE) {
        attrs.size = iter.get_next()?;
    }
    if attrs.has_attr(FileAttrsFlags::ID) {
        attrs.uid = iter.get_next()?;
        attrs.gid = iter.get_next()?;
    }
    if attrs.has_attr(FileAttrsFlags::PERMISSIONS) {
        attrs.st_mode = iter.get_next()?;

        let filetype = attrs.st_mode & S_IFMT;

        // If filetype is specified, then make sure it is valid.
        if filetype != 0 && FileType::from_u32(filetype).is_none() {
            return Err(V::Error::invalid_value(
                Unexpected::Unsigned(filetype as u64),
                &"Expected valid filetype specified in POSIX",
            ));
        }
    }

    let into_timestamp = |elapsed: u32| {
        let timestamp = UnixTimeStamp::from_raw(elapsed).ok_or_else(|| {
            V::Error::invalid_value(
                Unexpected::Unsigned(elapsed as u64),
                &"Invalid UnixTimeStamp (seconds)",
            )
        })?;

        Ok(timestamp)
    };

    if attrs.has_attr(FileAttrsFlags::TIME) {
        attrs.atime = into_timestamp(iter.get_next()?)?;
        attrs.mtime = into_timestamp(iter.get_next()?)?;
    }

    if attrs.has_attr(FileAttrsFlags::EXTENSIONS) {
        let extension_pairs: u32 = iter.get_next()?;
        for _i in 0..extension_pairs {
            let _name: &[u8] = iter.get_next()?;
            let _value: &[u8] = iter.get_next()?;
        }
    }

    attrs.flags.remove(FileAttrsFlags::EXTENSIONS);

    Ok(attrs)
});

#[cfg(test)]
mod tests {
    use super::{FileAttrs, FileAttrsFlags, FileType, Permissions, UnixTimeStamp};

    use super::constants::{
        SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_PERMISSIONS, SSH_FILEXFER_ATTR_SIZE,
        SSH_FILEXFER_ATTR_UIDGID,
    };

    // Test getter and setters

    fn get_unix_timestamps() -> (UnixTimeStamp, UnixTimeStamp) {
        (
            UnixTimeStamp::from_raw(2).unwrap(),
            UnixTimeStamp::from_raw(150).unwrap(),
        )
    }

    #[test]
    fn test_set_get_size() {
        let mut attrs = FileAttrs::default();
        attrs.set_size(2333);
        assert_eq!(attrs.get_size().unwrap(), 2333);
    }

    #[test]
    fn test_set_get_id() {
        let mut attrs = FileAttrs::default();
        attrs.set_id(u32::MAX, 1000);
        assert_eq!(attrs.get_id().unwrap(), (u32::MAX, 1000));
    }

    #[test]
    fn test_set_get_permissions() {
        let mut attrs = FileAttrs::default();
        attrs.set_permissions(Permissions::SET_GID);
        assert_eq!(attrs.get_permissions().unwrap(), Permissions::SET_GID);
    }

    #[test]
    fn test_set_get_time() {
        let (atime, mtime) = get_unix_timestamps();

        let mut attrs = FileAttrs::default();
        attrs.set_time(atime, mtime);
        assert_eq!(attrs.get_time().unwrap(), (atime, mtime));
    }

    // Test Serialize and Deserialize

    use serde_test::{assert_de_tokens, assert_tokens, Token};

    #[test]
    fn test_file_attr_flags() {
        assert_tokens(&FileAttrsFlags::empty(), &[Token::U32(0)]);
        assert_tokens(&FileAttrsFlags::SIZE, &[Token::U32(SSH_FILEXFER_ATTR_SIZE)]);
        assert_tokens(&FileAttrsFlags::ID, &[Token::U32(SSH_FILEXFER_ATTR_UIDGID)]);
        assert_tokens(
            &FileAttrsFlags::PERMISSIONS,
            &[Token::U32(SSH_FILEXFER_ATTR_PERMISSIONS)],
        );
        assert_tokens(
            &FileAttrsFlags::TIME,
            &[Token::U32(SSH_FILEXFER_ATTR_ACMODTIME)],
        );
    }

    fn init_attrs(f: impl FnOnce(&mut FileAttrs)) -> FileAttrs {
        let mut attrs = FileAttrs::default();
        f(&mut attrs);
        attrs
    }

    #[test]
    fn test_ser_de_size() {
        assert_tokens(
            &init_attrs(|attrs| attrs.set_size(2333)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_SIZE),
                Token::U64(2333),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_id() {
        assert_tokens(
            &init_attrs(|attrs| attrs.set_id(u32::MAX, 1000)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_UIDGID),
                Token::U32(u32::MAX),
                Token::U32(1000),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_permissions_and_filetype() {
        assert_tokens(
            &init_attrs(|attrs| attrs.set_permissions(Permissions::WRITE_BY_OTHER)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_PERMISSIONS),
                Token::U32(Permissions::WRITE_BY_OTHER.bits()),
                Token::TupleEnd,
            ],
        );

        assert_de_tokens(
            &init_attrs(|attrs| {
                attrs.set_permissions(Permissions::WRITE_BY_OTHER);
                attrs.st_mode = Permissions::WRITE_BY_OTHER.bits() | FileType::Socket as u32;
            }),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_PERMISSIONS),
                Token::U32(Permissions::WRITE_BY_OTHER.bits() | FileType::Socket as u32),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_time() {
        let (atime, mtime) = get_unix_timestamps();

        assert_tokens(
            &init_attrs(|attrs| attrs.set_time(atime, mtime)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_ACMODTIME),
                Token::U32(atime.into_raw()),
                Token::U32(mtime.into_raw()),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_all() {
        let (atime, mtime) = get_unix_timestamps();

        assert_tokens(
            &init_attrs(|attrs| {
                attrs.set_size(2333);
                attrs.set_id(u32::MAX, 1000);
                attrs.set_permissions(Permissions::READ_BY_OWNER);
                attrs.set_time(atime, mtime);
            }),
            &[
                Token::Tuple { len: 1 },
                Token::U32(
                    SSH_FILEXFER_ATTR_SIZE
                        | SSH_FILEXFER_ATTR_UIDGID
                        | SSH_FILEXFER_ATTR_PERMISSIONS
                        | SSH_FILEXFER_ATTR_ACMODTIME,
                ),
                Token::U64(2333),                              // size
                Token::U32(u32::MAX),                          // uid
                Token::U32(1000),                              // gid
                Token::U32(Permissions::READ_BY_OWNER.bits()), // permissions
                Token::U32(atime.into_raw()),                  // atime
                Token::U32(mtime.into_raw()),                  // mtime
                Token::TupleEnd,
            ],
        );
    }
}
