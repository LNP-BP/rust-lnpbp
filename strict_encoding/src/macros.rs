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

#[macro_export]
macro_rules! strict_decode_self {
    ( $decoder:ident; $($item:ident),+ ) => {
        {
            Self {
            $(
                $item: StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
}

#[macro_export]
macro_rules! impl_enum_strict_encoding {
    ($type:ty) => {
        impl $crate::strict_encoding::StrictEncode for $type {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(
                &self,
                e: E,
            ) -> Result<usize, $crate::strict_encoding::Error> {
                use ::num_traits::ToPrimitive;

                match self.to_u8() {
                    Some(result) => result.strict_encode(e),
                    None => {
                        Err($crate::strict_encoding::Error::EnumValueOverflow(
                            stringify!($type).to_string(),
                        ))
                    }
                }
            }
        }

        impl $crate::strict_encoding::StrictDecode for $type {
            #[inline]
            fn strict_decode<D: ::std::io::Read>(
                d: D,
            ) -> Result<Self, $crate::strict_encoding::Error> {
                use ::num_traits::FromPrimitive;

                let value = u8::strict_decode(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => {
                        Err($crate::strict_encoding::Error::EnumValueNotKnown(
                            stringify!($type).to_string(),
                            value,
                        ))
                    }
                }
            }
        }
    };
}
