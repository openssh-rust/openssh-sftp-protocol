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
        attrs.mtime = iter.get_next()?;
        attrs.atime = iter.get_next()?;
    }
    if attrs.has_attr(SSH_FILEXFER_ATTR_EXTENDED) {
        attrs.extensions = iter.get_next()?;
    }

    Ok(attrs)
});

#[cfg(test)]
mod tests {
    use super::{Extensions, FileAttrs};

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
}
