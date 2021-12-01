#![forbid(unsafe_code)]

pub extern crate serde;
pub extern crate ssh_format;
pub extern crate vec_strings;

mod seq_iter;
mod visitor;

pub mod constants;
pub mod extensions;
pub mod file;
pub mod request;
pub mod response;

pub type Handle = [u8];
pub type HandleOwned = Box<[u8]>;
