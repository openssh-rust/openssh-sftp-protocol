use super::constants;
use super::{extensions::Extensions, seq_iter::SeqIter, visitor::impl_visitor};

use core::ops::{Deref, DerefMut};

use bitflags::bitflags;

use serde::ser::{Serialize, SerializeTuple, Serializer};

use once_cell::sync::OnceCell;
use shared_arena::{ArenaBox, SharedArena};

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
            SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_EXTENDED, SSH_FILEXFER_ATTR_PERMISSIONS,
            SSH_FILEXFER_ATTR_SIZE, SSH_FILEXFER_ATTR_UIDGID,
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
        if self.intersects(FileAttrsFlags::EXTENSIONS) {
            flags |= SSH_FILEXFER_ATTR_EXTENDED;
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

#[derive(Debug, Default, Clone)]
pub struct FileAttrs {
    flags: FileAttrsFlags,

    /// present only if flag SSH_FILEXFER_ATTR_SIZE
    size: u64,

    /// present only if flag SSH_FILEXFER_ATTR_UIDGID
    uid: u32,
    gid: u32,

    /// present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
    permissions: u32,

    /// present only if flag SSH_FILEXFER_ATTR_ACMODTIME
    atime: u32,
    mtime: u32,

    /// present only if flag SSH_FILEXFER_ATTR_EXTENDED
    extensions: Extensions,
}

impl PartialEq for FileAttrs {
    fn eq(&self, other: &Self) -> bool {
        self.get_size() == other.get_size()
            && self.get_id() == other.get_id()
            && self.get_permissions() == other.get_permissions()
            && self.get_time() == other.get_time()
            && self.get_extensions() == other.get_extensions()
    }
}

impl Eq for FileAttrs {}

impl FileAttrs {
    #[inline]
    pub fn new() -> Self {
        Self::default()
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

    pub fn set_permissions(&mut self, permissions: u32) {
        self.flags |= FileAttrsFlags::PERMISSIONS;
        self.permissions = permissions;
    }

    pub fn set_time(&mut self, atime: u32, mtime: u32) {
        self.flags |= FileAttrsFlags::TIME;
        self.atime = atime;
        self.mtime = mtime;
    }

    pub fn set_extensions(&mut self, extensions: Extensions) {
        self.flags |= FileAttrsFlags::EXTENSIONS;
        self.extensions = extensions;
    }

    fn has_attr(&self, flag: FileAttrsFlags) -> bool {
        self.flags.intersects(flag)
    }

    fn getter_impl<T>(&self, flag: FileAttrsFlags, val: T) -> Option<T> {
        if self.has_attr(flag) {
            Some(val)
        } else {
            None
        }
    }

    pub fn get_size(&self) -> Option<u64> {
        self.getter_impl(FileAttrsFlags::SIZE, self.size)
    }

    /// Return uid and gid
    pub fn get_id(&self) -> Option<(u32, u32)> {
        self.getter_impl(FileAttrsFlags::ID, (self.uid, self.gid))
    }

    pub fn get_permissions(&self) -> Option<u32> {
        self.getter_impl(FileAttrsFlags::PERMISSIONS, self.permissions)
    }

    /// Return atime and mtime
    pub fn get_time(&self) -> Option<(u32, u32)> {
        self.getter_impl(FileAttrsFlags::TIME, (self.atime, self.mtime))
    }

    pub fn get_extensions(&self) -> Option<&Extensions> {
        self.getter_impl(FileAttrsFlags::EXTENSIONS, &self.extensions)
    }

    pub fn get_extensions_mut(&mut self) -> Option<&mut Extensions> {
        if self.has_attr(FileAttrsFlags::EXTENSIONS) {
            Some(&mut self.extensions)
        } else {
            None
        }
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
            tuple_serializer.serialize_element(&perm)?;
        }

        if let Some((atime, mtime)) = self.get_time() {
            tuple_serializer.serialize_element(&atime)?;
            tuple_serializer.serialize_element(&mtime)?;
        }

        if let Some(extensions) = self.get_extensions() {
            tuple_serializer.serialize_element(&extensions)?;
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
        attrs.permissions = iter.get_next()?;
    }
    if attrs.has_attr(FileAttrsFlags::TIME) {
        attrs.atime = iter.get_next()?;
        attrs.mtime = iter.get_next()?;
    }
    if attrs.has_attr(FileAttrsFlags::EXTENSIONS) {
        attrs.extensions = iter.get_next()?;
    }

    Ok(attrs)
});

#[derive(Debug)]
pub struct FileAttrsBox(pub ArenaBox<FileAttrs>);

impl FileAttrsBox {
    /// Return a shared arena that can be used to allocate
    /// `FileAttrs` efficiently.
    pub fn get_shared_arena() -> &'static SharedArena<FileAttrs> {
        static ARENA: OnceCell<SharedArena<FileAttrs>> = OnceCell::new();

        ARENA.get_or_init(SharedArena::new)
    }

    /// Create `ArenaBox` on shared_arena and move `self` onto it.
    pub fn alloc(file_attrs: FileAttrs) -> Self {
        Self(Self::get_shared_arena().alloc(file_attrs))
    }
}

impl Clone for FileAttrsBox {
    fn clone(&self) -> Self {
        Self::alloc(self.0.clone())
    }
}

impl Deref for FileAttrsBox {
    type Target = FileAttrs;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for FileAttrsBox {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl Serialize for FileAttrsBox {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (*self.0).serialize(serializer)
    }
}

impl<'de> crate::visitor::Deserialize<'de> for FileAttrsBox {
    fn deserialize<D: crate::visitor::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        Ok(Self::alloc(FileAttrs::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{Extensions, FileAttrs, FileAttrsFlags};

    use super::constants::{
        SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_EXTENDED, SSH_FILEXFER_ATTR_PERMISSIONS,
        SSH_FILEXFER_ATTR_SIZE, SSH_FILEXFER_ATTR_UIDGID,
    };

    // Test getter and setters

    fn get_extensions() -> Extensions {
        let mut extensions = Extensions::default();
        for i in 0..100 {
            extensions.add_extension(&i.to_string(), &(i + 1).to_string());
        }
        extensions
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
        attrs.set_permissions(0x102);
        assert_eq!(attrs.get_permissions().unwrap(), 0x102);
    }

    #[test]
    fn test_set_get_time() {
        let mut attrs = FileAttrs::default();
        attrs.set_time(2, 150);
        assert_eq!(attrs.get_time().unwrap(), (2, 150));
    }

    #[test]
    fn test_set_get_extensions() {
        let extensions = get_extensions();

        let mut attrs = FileAttrs::default();
        attrs.set_extensions(extensions.clone());
        assert_eq!(attrs.get_extensions().unwrap(), &extensions);
        assert_eq!(attrs.get_extensions_mut().unwrap(), &extensions);
    }

    // Test Serialize and Deserialize

    use serde_test::{assert_tokens, Token};

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
        assert_tokens(
            &FileAttrsFlags::EXTENSIONS,
            &[Token::U32(SSH_FILEXFER_ATTR_EXTENDED)],
        );

        assert_tokens(
            &FileAttrsFlags::all(),
            &[Token::U32(
                SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_UIDGID
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME
                    | SSH_FILEXFER_ATTR_EXTENDED,
            )],
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
    fn test_ser_de_permissions() {
        assert_tokens(
            &init_attrs(|attrs| attrs.set_permissions(0x102)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_PERMISSIONS),
                Token::U32(0x102),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_time() {
        assert_tokens(
            &init_attrs(|attrs| attrs.set_time(2, 150)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_ACMODTIME),
                Token::U32(2),
                Token::U32(150),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_extensions() {
        let mut extensions = Extensions::default();
        extensions.add_extension("1", "@");

        assert_tokens(
            &init_attrs(|attrs| attrs.set_extensions(extensions)),
            &[
                Token::Tuple { len: 1 },
                Token::U32(SSH_FILEXFER_ATTR_EXTENDED),
                // Start of extensions
                Token::Tuple { len: 3 },
                Token::U32(1),
                Token::BorrowedStr("1"),
                Token::BorrowedStr("@"),
                Token::TupleEnd,
                // End of extensions
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_ser_de_all() {
        let mut extensions = Extensions::default();
        extensions.add_extension("1", "@");

        assert_tokens(
            &init_attrs(|attrs| {
                attrs.set_size(2333);
                attrs.set_id(u32::MAX, 1000);
                attrs.set_permissions(0x102);
                attrs.set_time(2, 150);
                attrs.set_extensions(extensions);
            }),
            &[
                Token::Tuple { len: 1 },
                Token::U32(
                    SSH_FILEXFER_ATTR_SIZE
                        | SSH_FILEXFER_ATTR_UIDGID
                        | SSH_FILEXFER_ATTR_PERMISSIONS
                        | SSH_FILEXFER_ATTR_ACMODTIME
                        | SSH_FILEXFER_ATTR_EXTENDED,
                ),
                Token::U64(2333),     // size
                Token::U32(u32::MAX), // uid
                Token::U32(1000),     // gid
                Token::U32(0x102),    // permissions
                Token::U32(2),        // atime
                Token::U32(150),      // mtime
                // Start of extensions
                Token::Tuple { len: 3 },
                Token::U32(1),
                Token::BorrowedStr("1"),
                Token::BorrowedStr("@"),
                Token::TupleEnd,
                // End of extensions
                Token::TupleEnd,
            ],
        );
    }
}
