#![allow(dead_code)]

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
#[strict_encoding_crate(strict_encoding)]
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
#[strict_encoding_enum(value)]
#[repr(u8)]
enum ByValue {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

#[derive(StrictEncode, StrictDecode)]
enum CustomErr<Err>
where
    Err: std::error::Error + StrictEncode + StrictDecode,
{
    Other(Err),
}

fn main() {
    assert_eq!(ByValue::Bit64.strict_serialize().unwrap(), vec![8])
}
