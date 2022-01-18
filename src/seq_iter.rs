#![forbid(unsafe_code)]

use core::marker::PhantomData;

use serde::de::{Error, SeqAccess};
use serde::Deserialize;

pub(crate) struct SeqIter<'de, V: SeqAccess<'de>>(usize, V, PhantomData<&'de ()>);

impl<'de, V: SeqAccess<'de>> SeqIter<'de, V> {
    pub(crate) fn new(seq: V) -> Self {
        Self(0, seq, PhantomData)
    }

    pub(crate) fn get_next<T: Deserialize<'de>>(&mut self) -> Result<T, V::Error> {
        let res = self
            .1
            .next_element()?
            .ok_or_else(|| Error::invalid_length(self.0, &"Not long enough"));
        self.0 += 1;
        res
    }
}
