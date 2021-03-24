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

/// Strinct encode a list of items
#[macro_export]
macro_rules! strict_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.strict_encode(&mut $encoder)?;
            )+
            len
        }
    };

    ( $encoder:ident; $len:ident; $($item:expr),+ ) => {
        {
            $(
                $len += $item.strict_encode(&mut $encoder)?;
            )+
            $len
        }
    }
}

/// Strict decode a list of items
#[macro_export]
macro_rules! strict_decode_self {
    ( $decoder:ident; $($item:ident),+ ) => {
        {
            Self {
            $(
                $item: ::strict_encoding::StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
    ( $decoder:ident; $($item:ident),+ ; crate) => {
        {
            Self {
            $(
                $item: $crate::StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
}

/// Implement strict encoding for enums
#[macro_export]
macro_rules! impl_enum_strict_encoding {
    ($type:ty) => {
        impl ::strict_encoding::StrictEncode for $type {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(
                &self,
                e: E,
            ) -> Result<usize, ::strict_encoding::Error> {
                use ::num_traits::ToPrimitive;

                match self.to_u8() {
                    Some(result) => result.strict_encode(e),
                    None => Err(::strict_encoding::Error::EnumValueOverflow(
                        stringify!($type).to_string(),
                    )),
                }
            }
        }

        impl ::strict_encoding::StrictDecode for $type {
            #[inline]
            fn strict_decode<D: ::std::io::Read>(
                d: D,
            ) -> Result<Self, ::strict_encoding::Error> {
                use ::num_traits::FromPrimitive;

                let value = u8::strict_decode(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => Err(::strict_encoding::Error::EnumValueNotKnown(
                        stringify!($type).to_string(),
                        value,
                    )),
                }
            }
        }
    };
}
