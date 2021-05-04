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
#[strict_encoding(crate = strict_encoding)]
enum Hi {
    /// Docstring
    First(u8),
    Second(Heap),
    Third,
    Fourth {
        heap: Heap,
    },
    Seventh,
}

#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_order)]
#[repr(u8)]
enum ByOrder {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value)]
#[repr(u8)]
enum ByValue {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

// All variants have custom values apart from the first one, which should has
// value = 1
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value)]
#[repr(u8)]
enum CustomValues {
    Bit8 = 1,

    #[strict_encoding(value = 11)]
    Bit16 = 2,

    #[strict_encoding(value = 12)]
    Bit32 = 4,

    #[strict_encoding(value = 13)]
    Bit64 = 8,
}

#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_order, repr = u16)]
#[repr(u16)]
enum U16 {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
}

#[derive(StrictEncode, StrictDecode)]
struct Skipping {
    pub data: Vec<u8>,

    // This will initialize the field upon decoding with Option::default()
    // value
    #[strict_encoding(skip)]
    pub ephemeral: Option<bool>,
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
