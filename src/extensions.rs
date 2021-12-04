use super::seq_iter::SeqIter;
use super::visitor::impl_visitor;

use core::iter::{IntoIterator, Iterator};

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

    pub fn reserve(&mut self, extensions: u32) {
        self.0.reserve(extensions * 2);
    }

    pub fn reserve_strs(&mut self, cnt: usize) {
        self.0.reserve(cnt);
    }

    pub fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit();
    }

    pub fn get(&self, index: u32) -> Option<(&str, &str)> {
        Some((self.0.get(index * 2)?, self.0.get(index * 2 + 1).unwrap()))
    }

    /// Accumulate length of all strings.
    pub fn strs_len(&self) -> u32 {
        self.0.strs_len()
    }

    pub fn len(&self) -> u32 {
        self.0.len() / 2
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> ExtensionsIter<'_> {
        ExtensionsIter(self.0.iter())
    }

    /// Return the underlying Strings
    pub fn get_strings(&self) -> &Strings {
        &self.0
    }

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

impl_visitor!(
    Extensions,
    ExtensionsVisitor,
    "A u32 length and &[str]",
    seq,
    {
        let mut iter = SeqIter::new(seq);

        let len: u32 = iter.get_next()?;

        let mut extensions = Extensions::default();
        extensions.reserve(len as usize);

        for _ in 0..len {
            extensions.add_extension(iter.get_next()?, iter.get_next()?);
        }

        Ok(extensions)
    }
);

impl<'a> IntoIterator for &'a Extensions {
    type Item = (&'a str, &'a str);
    type IntoIter = ExtensionsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone, Debug)]
pub struct ExtensionsIter<'a>(StringsIter<'a>);

impl<'a> Iterator for ExtensionsIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        Some((self.0.next()?, self.0.next().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::Extensions;

    use once_cell::sync::OnceCell;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn test() {
        let mut extensions = Extensions::default();
        let input_strs: Vec<String> = (0..1024).map(|n| n.to_string()).collect();

        assert!(extensions.is_empty());

        for (i, input_str) in input_strs.iter().enumerate() {
            extensions.add_extension(input_str, "1");
            assert_eq!(extensions.len() as usize, i + 1);
        }

        for (i, input_str) in input_strs.iter().enumerate() {
            assert_eq!(
                extensions.get(i.try_into().unwrap()).unwrap(),
                (input_str.as_str(), "1")
            );
        }

        for (input_str, each) in input_strs.iter().zip(extensions.iter()) {
            assert_eq!(each, (input_str.as_str(), "1"));
        }
    }

    // Test using serde_test

    #[test]
    fn test_ser_de_empty_serde() {
        assert_tokens(
            &Extensions::default(),
            &[Token::Tuple { len: 1 }, Token::U32(0), Token::TupleEnd],
        );
    }

    fn assert_ser_de_serde(extensions: &'static Extensions) {
        // Test Extensions
        let mut tokens = vec![
            Token::Tuple {
                len: 1 + (extensions.len() as usize) * 2,
            },
            Token::U32(extensions.len().try_into().unwrap()),
        ];

        for (name, data) in extensions {
            tokens.push(Token::BorrowedStr(name));
            tokens.push(Token::BorrowedStr(data));
        }

        tokens.push(Token::TupleEnd);

        assert_tokens(extensions, &tokens);
    }

    fn get_extensions() -> &'static Extensions {
        static STRINGS: OnceCell<Extensions> = OnceCell::new();

        STRINGS.get_or_init(|| {
            let mut extensions = Extensions::default();
            for i in 0..1024 {
                extensions.add_extension(&i.to_string(), &(i + 20).to_string());
            }
            extensions
        })
    }

    #[test]
    fn test_ser_de_serde() {
        assert_ser_de_serde(get_extensions());
    }

    // Test using serde_json

    fn assert_ser_de_json(extensions: &Extensions) {
        assert_eq!(
            serde_json::from_str::<'_, Extensions>(&serde_json::to_string(extensions).unwrap())
                .unwrap(),
            *extensions
        );
    }

    #[test]
    fn test_ser_de_serde_json() {
        assert_ser_de_json(get_extensions());
    }
}
