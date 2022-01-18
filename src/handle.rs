use std::borrow::{Borrow, ToOwned};
use std::convert::AsRef;
use std::mem::transmute;
use std::ops::Deref;

use vec_strings::SmallArrayBox;

#[derive(Debug, Clone)]
pub struct HandleOwned(pub(crate) SmallArrayBox<u8, 4>);

impl Deref for HandleOwned {
    type Target = Handle;

    fn deref(&self) -> &Self::Target {
        unsafe { transmute(self.0.deref()) }
    }
}

impl Borrow<Handle> for HandleOwned {
    fn borrow(&self) -> &Handle {
        self.deref()
    }
}

impl AsRef<Handle> for HandleOwned {
    fn as_ref(&self) -> &Handle {
        self.deref()
    }
}

#[derive(Debug, Eq, PartialEq, serde::Serialize)]
#[repr(transparent)]
pub struct Handle([u8]);

impl Handle {
    pub const fn into_inner(&self) -> &[u8] {
        &self.0
    }
}

impl ToOwned for Handle {
    type Owned = HandleOwned;

    fn to_owned(&self) -> Self::Owned {
        HandleOwned(SmallArrayBox::new(self.into_inner().iter().copied()))
    }
}
