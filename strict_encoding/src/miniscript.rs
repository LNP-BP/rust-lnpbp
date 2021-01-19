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

use std::fmt::Display;
use std::io;
use std::str::FromStr;

use miniscript::descriptor::DescriptorSinglePub;
use miniscript::{policy, Miniscript, MiniscriptKey};

use crate::{Error, StrictDecode, StrictEncode};

impl StrictEncode for DescriptorSinglePub {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.key, self.origin))
    }
}

impl StrictDecode for DescriptorSinglePub {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; key, origin; crate))
    }
}

impl<Pk> StrictEncode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey + FromStr,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_string().strict_encode(e)
    }
}

impl<Pk> StrictDecode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey + FromStr,
    <Pk as FromStr>::Err: Display,
    <Pk as MiniscriptKey>::Hash: FromStr,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: Display,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::strict_decode(d)?.parse().map_err(|_| {
            Error::DataIntegrityError(s!("Unparsable miniscript policy string"))
        })
    }
}

impl<Pk, Ctx> StrictEncode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey + FromStr,
    Ctx: miniscript::ScriptContext,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_string().strict_encode(e)
    }
}

impl<Pk, Ctx> StrictDecode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey + FromStr,
    <Pk as FromStr>::Err: Display,
    <Pk as MiniscriptKey>::Hash: FromStr,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: Display,
    Ctx: miniscript::ScriptContext,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::strict_decode(d)?.parse().map_err(|_| {
            Error::DataIntegrityError(s!("Unparsable miniscript string"))
        })
    }
}
