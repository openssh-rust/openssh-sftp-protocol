#![forbid(unsafe_code)]

pub(crate) use std::fmt;

pub(crate) use serde::{
    de::{Deserializer, SeqAccess, Visitor},
    Deserialize,
};

macro_rules! impl_visitor {
    ($type:ident, $visitor_name: ident, $expecting_msg:expr, $seq_name: ident, $impl:block) => {
        impl<'de> crate::visitor::Deserialize<'de> for $type {
            fn deserialize<D: crate::visitor::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct $visitor_name;

                impl<'de> crate::visitor::Visitor<'de> for $visitor_name {
                    type Value = $type;

                    fn expecting(
                        &self,
                        formatter: &mut crate::visitor::fmt::Formatter,
                    ) -> crate::visitor::fmt::Result {
                        write!(formatter, $expecting_msg)
                    }

                    fn visit_seq<V>(self, $seq_name: V) -> Result<Self::Value, V::Error>
                    where
                        V: crate::visitor::SeqAccess<'de>,
                    {
                        $impl
                    }
                }

                // Pass a dummy size here since ssh_format doesn't care
                deserializer.deserialize_tuple(u32::MAX as usize, $visitor_name)
            }
        }
    };
}

pub(crate) use impl_visitor;
