#![allow(dead_code, bare_trait_objects)]

use strict_encoding::{StrictDecode, StrictEncode};

#[derive(StrictEncode, StrictDecode)]
struct Me(u8);

#[derive(StrictEncode, StrictDecode)]
struct One {
    a: Vec<u8>,
}

#[derive(StrictEncode, StrictDecode)]
struct Heap(Box<[u8]>);

#[derive(StrictEncode, StrictDecode)]
struct You {
    //    a: (),
    b: Vec<u8>,
}

#[derive(StrictEncode, StrictDecode)]
struct Other {
    //    a: (),
    b: u8,
}

#[derive(StrictEncode, StrictDecode)]
enum Hi {
    /// Docstring
    First(u8),
    Second(Heap),
    Third,
    Fourth {
        other: Other,
    },
    Seventh,
}

#[derive(StrictEncode, StrictDecode)]
enum CustomErr<Err>
where
    Err: std::error::Error + StrictEncode + StrictDecode,
{
    Other(Err),
}

fn main() {}
