// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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

#[macro_use]
extern crate amplify_derive;
extern crate serde_crate as serde;

use clap::{AppSettings, Clap};
use serde::Serialize;
use std::fmt::{Debug, Display};
use std::io::{self, Read};
use std::str::FromStr;

use base58::{FromBase58, ToBase58};
use bitcoin::hashes::hex::{FromHex, ToHex};
use lnpbp::bech32::Blob;

#[derive(Clap, Clone, Debug)]
#[clap(
    name = "lnpbp",
    bin_name = "lnpbp",
    author,
    version,
    about = "Command-line tool for working with LNP/BP stack",
    setting = AppSettings::ColoredHelp,
)]
pub struct Opts {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum Command {
    /// Commands for working with consignments
    Convert {
        /// Original data; if none are given reads from STDIN
        data: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(
    Clap, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display,
)]
pub enum Format {
    /// Format according to the rust debug rules
    #[display("debug")]
    Debug,

    /// Format according to Bech32 encoding
    #[display("bech32")]
    Bech32,

    /// Format according to Base58 encoding
    #[display("base58")]
    Base58,

    /// Format according to Base64 encoding
    #[display("base64")]
    Base64,

    /// Format as YAML
    #[display("yaml")]
    Yaml,

    /// Format as JSON
    #[display("json")]
    Json,

    /// Format according to the strict encoding rules
    #[display("hex")]
    Hexadecimal,

    /// Format as a rust array (using hexadecimal byte values)
    #[display("rust")]
    Rust,

    /// Produce binary (raw) output
    #[display("raw")]
    Raw,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "debug" => Format::Debug,
            "bech32" => Format::Bech32,
            "base58" => Format::Base58,
            "base64" => Format::Base64,
            "yaml" => Format::Yaml,
            "json" => Format::Json,
            "hex" => Format::Hexadecimal,
            "raw" | "bin" | "binary" => Format::Raw,
            "rust" => Format::Rust,
            other => Err(format!("Unknown format: {}", other))?,
        })
    }
}

fn input_read<T>(data: Option<String>, format: Format) -> Result<T, String>
where
    T: From<Vec<u8>> + FromStr + for<'de> serde::Deserialize<'de>,
    <T as FromStr>::Err: Display,
{
    let data = data
        .map(|d| d.as_bytes().to_vec())
        .ok_or(String::default())
        .or_else(|_| -> Result<Vec<u8>, String> {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .as_ref()
                .map_err(io::Error::to_string)?;
            Ok(buf)
        })?;
    let s = &String::from_utf8_lossy(&data);
    Ok(match format {
        Format::Bech32 => T::from_str(s).map_err(|err| err.to_string())?,
        Format::Base58 => {
            T::from(s.from_base58().map_err(|err| {
                format!("Incorrect Base58 encoding: {:?}", err)
            })?)
        }
        Format::Base64 => T::from(
            base64::decode(&data)
                .map_err(|err| format!("Incorrect Base64 encoding: {}", err))?,
        ),
        Format::Yaml => {
            serde_yaml::from_str(s).map_err(|err| err.to_string())?
        }
        Format::Json => {
            serde_json::from_str(s).map_err(|err| err.to_string())?
        }
        Format::Hexadecimal => {
            T::from(Vec::<u8>::from_hex(s).map_err(|err| err.to_string())?)
        }
        Format::Raw => T::from(data),
        _ => Err(format!("Can't read data from {} format", format))?,
    })
}

fn output_write<T>(
    mut f: impl io::Write,
    data: T,
    format: Format,
) -> Result<(), String>
where
    T: AsRef<[u8]> + Debug + Display + Serialize,
{
    match format {
        Format::Debug => write!(f, "{:#?}", data),
        Format::Bech32 => write!(f, "{}", data),
        Format::Base58 => write!(f, "{}", data.as_ref().to_base58()),
        Format::Base64 => write!(f, "{}", base64::encode(data.as_ref())),
        Format::Yaml => write!(
            f,
            "{}",
            serde_yaml::to_string(data.as_ref())
                .as_ref()
                .map_err(serde_yaml::Error::to_string)?
        ),
        Format::Json => write!(
            f,
            "{}",
            serde_json::to_string(data.as_ref())
                .as_ref()
                .map_err(serde_json::Error::to_string)?
        ),
        Format::Hexadecimal => write!(f, "{}", data.as_ref().to_hex()),
        Format::Rust => write!(f, "{:#04X?}", data.as_ref()),
        Format::Raw => f.write(data.as_ref()).map(|_| ()),
    }
    .as_ref()
    .map_err(io::Error::to_string)?;
    Ok(())
}

fn main() -> Result<(), String> {
    let opts = Opts::parse();

    match opts.command {
        Command::Convert {
            data,
            input,
            output,
        } => {
            let data: Blob = input_read(data, input)?;
            output_write(io::stdout(), data, output)?;
        }
    }

    Ok(())
}
