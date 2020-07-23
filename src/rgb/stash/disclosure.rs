// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Disclosure is the way to make certain confidential information about the
//! stash public.

// TODO: Implement disclosures

use std::io;

use crate::strict_encoding::{self, StrictDecode, StrictEncode};

#[derive(Clone, Debug)]
pub struct Disclosure {}

impl StrictEncode for Disclosure {
    fn strict_encode<E: io::Write>(&self, _: E) -> Result<usize, strict_encoding::Error> {
        unimplemented!()
    }
}

impl StrictDecode for Disclosure {
    fn strict_decode<D: io::Read>(_: D) -> Result<Self, strict_encoding::Error> {
        unimplemented!()
    }
}
