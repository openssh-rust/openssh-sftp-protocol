use core::fmt;
use core::iter::{IntoIterator, Iterator};

use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeTuple, Serializer};

pub use vec_strings::{Strings, StringsIter};

#[derive(Debug, Default, Eq, PartialEq, Clone, Hash)]
pub struct Extensions(Strings);

impl From<Extensions> for Strings {
    fn from(extensions: Extensions) -> Self {
        extensions.into_strings()
    }
}

impl<'a> From<&'a Extensions> for &'a Strings {
    fn from(extensions: &'a Extensions) -> Self {
        extensions.get_strings()
    }
}

impl Extensions {
    /// Return Some(...) if strs.len() is even.
    /// None otherwise.
    pub fn new(strs: Strings) -> Option<Self> {
        if strs.len() % 2 == 0 {
            Some(Self(strs))
        } else {
            None
        }
    }

    pub fn add_extension(&mut self, name: &str, data: &str) {
        self.0.push(name);
        self.0.push(data);
    }

    #[inline(always)]
    pub fn reserve(&mut self, extensions: usize) {
        self.0.reserve(extensions * 2);
    }

    #[inline(always)]
    pub fn reserve_strs(&mut self, cnt: usize) {
        self.0.reserve(cnt);
    }

    #[inline(always)]
    pub fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit();
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<(&str, &str)> {
        Some((self.0.get(index * 2)?, self.0.get(index * 2 + 1).unwrap()))
    }

    /// Accumulate length of all strings.
    #[inline(always)]
    pub fn strs_len(&self) -> u32 {
        self.0.strs_len()
    }

    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.0.len() / 2
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    pub fn iter(&self) -> ExtensionsIter<'_> {
        ExtensionsIter(self.0.iter())
    }

    /// Return the underlying Strings
    #[inline(always)]
    pub fn get_strings(&self) -> &Strings {
        &self.0
    }

    #[inline(always)]
    pub fn into_strings(self) -> Strings {
        self.0
    }
}

impl Serialize for Extensions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple_serializer = serializer.serialize_tuple(1 + self.0.len() as usize)?;

        tuple_serializer.serialize_element(&self.len())?;

        for (extension_name, extension_data) in self {
            tuple_serializer.serialize_element(extension_name)?;
            tuple_serializer.serialize_element(extension_data)?;
        }

        tuple_serializer.end()
    }
}

impl<'de> Deserialize<'de> for Extensions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExtensionsVisitor(usize);

        impl ExtensionsVisitor {
            fn get_next<'de, T, V>(&mut self, seq: &mut V) -> Result<T, V::Error>
            where
                T: Deserialize<'de>,
                V: SeqAccess<'de>,
            {
                let res = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(self.0, self));
                self.0 += 1;
                res
            }
        }

        impl<'de> Visitor<'de> for ExtensionsVisitor {
            type Value = Extensions;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "A u32 length and &[str]")
            }

            fn visit_seq<V>(mut self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let len: u32 = self.get_next(&mut seq)?;

                let mut extensions = Extensions::default();
                extensions.reserve(len as usize);

                for _ in 0..len {
                    extensions.add_extension(self.get_next(&mut seq)?, self.get_next(&mut seq)?);
                }

                Ok(extensions)
            }
        }

        // dummy size here since ssh_format doesn't care
        deserializer.deserialize_tuple(2, ExtensionsVisitor(0))
    }
}

impl<'a> IntoIterator for &'a Extensions {
    type Item = (&'a str, &'a str);
    type IntoIter = ExtensionsIter<'a>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ExtensionsIter<'a>(StringsIter<'a>);

impl<'a> Iterator for ExtensionsIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.0.next()?, self.0.next().unwrap()))
    }
}
