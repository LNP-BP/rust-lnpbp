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

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{self, blockdata::script::Error as ScriptError, Script};
use hex::{self, FromHex};
use miniscript::{self, Descriptor, Miniscript, ScriptContext, Terminal};

use super::TrackingKey;

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Hex encoding error: {0}
    #[from]
    Hex(hex::Error),

    /// Bitcoin script error: {0}
    #[from]
    Script(ScriptError),

    /// Miniscript error
    #[display("{0}")]
    Miniscript(String),
}

impl From<miniscript::Error> for Error {
    fn from(err: miniscript::Error) -> Self {
        Error::Miniscript(err.to_string())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
pub struct DescriptorGenerator {
    pub content: DescriptorContent,
    pub types: DescriptorTypes,
}

impl DescriptorGenerator {
    pub fn descriptor(&self) -> String {
        let single = self.content.is_singlesig();
        let mut d = vec![];
        if self.types.bare {
            d.push(if single { "pk" } else { "bare" });
        }
        if self.types.hashed {
            d.push(if single { "pkh" } else { "sh" });
        }
        if self.types.compat {
            d.push(if single { "sh_wpkh" } else { "sh_wsh" });
        }
        if self.types.segwit {
            d.push(if single { "wpkh" } else { "wsh" });
        }
        if self.types.taproot {
            d.push("tpk");
        }
        let data = match &self.content {
            DescriptorContent::SingleSig(key) => key.to_string(),
            DescriptorContent::MultiSig(threshold, keyset) => {
                format!(
                    "thresh_m({},{})",
                    threshold,
                    keyset
                        .iter()
                        .map(TrackingKey::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
            DescriptorContent::LockScript(_, script) => script.clone(),
        };
        format!("{}({})", d.join("|"), data)
    }

    pub fn pubkey_scripts_count(&self) -> u32 {
        self.types.bare as u32
            + self.types.hashed as u32
            + self.types.compat as u32
            + self.types.segwit as u32
            + self.types.taproot as u32
    }

    pub fn pubkey_scripts(
        &self,
        index: u32,
    ) -> Result<HashMap<DescriptorType, Script>, Error> {
        let mut scripts = HashMap::with_capacity(5);
        let single = if let DescriptorContent::SingleSig(_) = self.content {
            Some(self.content.public_key(index).expect("Can't fail"))
        } else {
            None
        };
        if self.types.bare {
            let d = if let Some(pk) = single {
                Descriptor::Pk(pk)
            } else {
                Descriptor::Bare(self.content.miniscript(index)?)
            };
            scripts.insert(DescriptorType::Bare, d.script_pubkey());
        }
        if self.types.hashed {
            let d = if let Some(pk) = single {
                Descriptor::Pkh(pk)
            } else {
                Descriptor::Sh(self.content.miniscript(index)?)
            };
            scripts.insert(DescriptorType::Hashed, d.script_pubkey());
        }
        if self.types.compat {
            let d = if let Some(pk) = single {
                Descriptor::ShWpkh(pk)
            } else {
                Descriptor::ShWsh(self.content.miniscript(index)?)
            };
            scripts.insert(DescriptorType::Compat, d.script_pubkey());
        }
        if self.types.segwit {
            let d = if let Some(pk) = single {
                Descriptor::Wpkh(pk)
            } else {
                Descriptor::Wsh(self.content.miniscript(index)?)
            };
            scripts.insert(DescriptorType::SegWit, d.script_pubkey());
        }
        /* TODO: Enable once Taproot will go live
        if self.taproot {
            scripts.push(content.taproot());
        }
         */
        Ok(scripts)
    }
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    StrictEncode,
    StrictDecode,
)]
pub enum DescriptorType {
    Bare,
    Hashed,
    Compat,
    SegWit,
    Taproot,
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Debug, StrictEncode, StrictDecode,
)]
pub struct DescriptorTypes {
    pub bare: bool,
    pub hashed: bool,
    pub compat: bool,
    pub segwit: bool,
    pub taproot: bool,
}

impl DescriptorTypes {
    pub fn has_match(&self, descriptor_type: DescriptorType) -> bool {
        match descriptor_type {
            DescriptorType::Bare => self.bare,
            DescriptorType::Hashed => self.hashed,
            DescriptorType::Compat => self.compat,
            DescriptorType::SegWit => self.segwit,
            DescriptorType::Taproot => self.taproot,
        }
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    StrictEncode,
    StrictDecode,
)]
pub enum DescriptorContent {
    SingleSig(TrackingKey),
    MultiSig(u8, Vec<TrackingKey>),
    LockScript(SourceType, String),
}

impl DescriptorContent {
    pub fn is_singlesig(&self) -> bool {
        match self {
            DescriptorContent::SingleSig(_) => true,
            _ => false,
        }
    }

    pub fn public_key(&self, index: u32) -> Option<bitcoin::PublicKey> {
        match self {
            DescriptorContent::SingleSig(key) => Some(key.public_key(index)),
            _ => None,
        }
    }

    pub fn miniscript<Ctx>(
        &self,
        index: u32,
    ) -> Result<Miniscript<bitcoin::PublicKey, Ctx>, Error>
    where
        Ctx: ScriptContext,
    {
        Ok(match self {
            DescriptorContent::SingleSig(key) => {
                let pk = key.public_key(index);
                Miniscript::from_ast(Terminal::PkK(pk))?
            }
            DescriptorContent::MultiSig(thresh, keyset) => {
                let ks = keyset
                    .into_iter()
                    .map(|key| key.public_key(index))
                    .collect();
                Miniscript::from_ast(Terminal::Multi(*thresh as usize, ks))?
            }
            DescriptorContent::LockScript(source_type, script) => {
                match source_type {
                    SourceType::Binary => {
                        let script = Script::from(Vec::from_hex(script)?);
                        Miniscript::parse(&script)?
                    }
                    SourceType::Assembly => {
                        // TODO: Parse assembly
                        let script = Script::from(Vec::from_hex(script)?);
                        Miniscript::parse(&script)?
                    }
                    SourceType::Miniscript => Miniscript::from_str(script)?,
                    SourceType::Policy => {
                        // TODO: Compiler will require changes to LNP/BP
                        // policy::Concrete::from_str(script)?.compile()?
                        Miniscript::from_str(script)?
                    }
                }
            }
        })
    }
}
