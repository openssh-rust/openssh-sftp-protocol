#![forbid(unsafe_code)]

pub extern crate serde;
pub extern crate shared_arena;
pub extern crate ssh_format;
pub extern crate vec_strings;

mod seq_iter;
mod visitor;

pub mod constants;
pub mod file_attrs;
pub mod open_options;
pub mod request;
pub mod response;

pub type Handle = [u8];
pub type HandleOwned = vec_strings::SmallArrayBox<u8, 4>;
