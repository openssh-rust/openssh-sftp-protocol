use super::{extensions::Extensions, seq_iter::SeqIter, visitor::impl_visitor};

use super::constants::{
    SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_EXTENDED, SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE, SSH_FILEXFER_ATTR_UIDGID,
};

use serde::ser::{Serialize, SerializeTuple, Serializer};

#[derive(Debug, Default, Clone)]
pub struct FileAttrs {
    flags: u32,

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
        self.flags |= SSH_FILEXFER_ATTR_SIZE;
        self.size = size;
    }

    pub fn set_id(&mut self, uid: u32, gid: u32) {
        self.flags |= SSH_FILEXFER_ATTR_UIDGID;
        self.uid = uid;
        self.gid = gid;
    }

    pub fn set_permissions(&mut self, permissions: u32) {
        self.flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        self.permissions = permissions;
    }

    pub fn set_time(&mut self, atime: u32, mtime: u32) {
        self.flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        self.atime = atime;
        self.mtime = mtime;
    }

    pub fn set_extensions(&mut self, extensions: Extensions) {
        self.flags |= SSH_FILEXFER_ATTR_EXTENDED;
        self.extensions = extensions;
    }

    fn has_attr(&self, attr_mask: u32) -> bool {
        (self.flags & attr_mask) != 0
    }

    fn getter_impl<T>(&self, attr_mask: u32, val: T) -> Option<T> {
        if self.has_attr(attr_mask) {
            Some(val)
        } else {
            None
        }
    }

    pub fn get_size(&self) -> Option<u64> {
        self.getter_impl(SSH_FILEXFER_ATTR_SIZE, self.size)
    }

    /// Return uid and gid
    pub fn get_id(&self) -> Option<(u32, u32)> {
        self.getter_impl(SSH_FILEXFER_ATTR_UIDGID, (self.uid, self.gid))
    }

    pub fn get_permissions(&self) -> Option<u32> {
        self.getter_impl(SSH_FILEXFER_ATTR_PERMISSIONS, self.permissions)
    }

    /// Return atime and mtime
    pub fn get_time(&self) -> Option<(u32, u32)> {
        self.getter_impl(SSH_FILEXFER_ATTR_ACMODTIME, (self.atime, self.mtime))
    }

    pub fn get_extensions(&self) -> Option<&Extensions> {
        self.getter_impl(SSH_FILEXFER_ATTR_EXTENDED, &self.extensions)
    }

    pub fn get_extensions_mut(&mut self) -> Option<&mut Extensions> {
        if (self.flags & SSH_FILEXFER_ATTR_EXTENDED) != 0 {
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
    let mut attrs = FileAttrs::default();

    let flags = iter.get_next()?;

    attrs.flags = flags;

    if attrs.has_attr(SSH_FILEXFER_ATTR_SIZE) {
        attrs.size = iter.get_next()?;
    }
    if attrs.has_attr(SSH_FILEXFER_ATTR_UIDGID) {
        attrs.uid = iter.get_next()?;
        attrs.gid = iter.get_next()?;
    }
    if attrs.has_attr(SSH_FILEXFER_ATTR_PERMISSIONS) {
        attrs.permissions = iter.get_next()?;
    }
    if attrs.has_attr(SSH_FILEXFER_ATTR_ACMODTIME) {
        attrs.atime = iter.get_next()?;
        attrs.mtime = iter.get_next()?;
    }
    if attrs.has_attr(SSH_FILEXFER_ATTR_EXTENDED) {
        attrs.extensions = iter.get_next()?;
    }

    Ok(attrs)
});

#[cfg(test)]
mod tests {
    use super::{Extensions, FileAttrs};

    use super::{
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
