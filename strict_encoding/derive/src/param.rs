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

use proc_macro2::Span;
use std::convert::TryInto;
use syn::{Error, Ident, LitInt, Path, Result};

use amplify::proc_attr::{
    ArgValue, ArgValueReq, AttrReq, LiteralClass, ParametrizedAttr, ValueClass,
};

#[derive(Clone)]
pub(crate) struct EncodingDerive {
    pub use_crate: Path,
    pub skip: bool,
    pub by_order: bool,
    pub value: Option<LitInt>,
    pub repr: Ident,
}

impl EncodingDerive {
    pub(crate) fn try_from(
        attr: &mut ParametrizedAttr,
        is_global: bool,
        is_enum: bool,
    ) -> Result<EncodingDerive> {
        let mut map = if is_global {
            map! {
                "crate" => ArgValueReq::with_default("strict_encoding")
            }
        } else {
            map! {
                "skip" => ArgValueReq::Prohibited
            }
        };

        if is_enum {
            if is_global {
                map.insert("by_order", ArgValueReq::Prohibited);
                map.insert("by_value", ArgValueReq::Prohibited);
                map.insert("repr", ArgValueReq::with_default(ident!(u8)));
            } else {
                map.insert(
                    "value",
                    ArgValueReq::Required {
                        default: None,
                        class: ValueClass::Literal(LiteralClass::Int),
                    },
                );
            }
        }

        attr.check(AttrReq::with(map))?;

        if attr.args.contains_key("by_value")
            && attr.args.contains_key("by_order")
        {
            return Err(Error::new(
                Span::call_site(),
                "`by_value` and `by_order` attributes can't be present together",
            ));
        }

        let repr: Ident = attr
            .args
            .get("repr")
            .expect("amplify_syn is broken")
            .clone()
            .try_into()
            .expect("amplify_syn is broken");

        match repr.to_string().as_str() {
            "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => {}
            _ => {
                return Err(Error::new(
                    Span::call_site(),
                    "`repr` requires integer type identifier",
                ))
            }
        }

        let use_crate = attr
            .args
            .get("crate")
            .cloned()
            .unwrap_or(ArgValue::from(ident!(crate)))
            .try_into()
            .expect("amplify_syn is broken");

        let value = attr
            .args
            .get("value")
            .map(|a| a.clone().try_into().expect("amplify_syn is broken"));

        let skip = attr.args.get("skip").is_some();

        let by_order = !attr.args.contains_key("by_value");

        Ok(EncodingDerive {
            use_crate,
            skip,
            by_order,
            repr,
            value,
        })
    }
}
