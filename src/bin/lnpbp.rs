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
extern crate clap;
#[macro_use]
extern crate amplify;
extern crate serde_crate as serde;

use amplify::hex;
use std::fmt::{Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::FromUtf8Error;
use std::{fmt, fs};

use amplify::hex::{FromHex, ToHex};
use base58::{FromBase58, FromBase58Error, ToBase58};
use clap::Parser;
use colorize::AnsiColor;
use lnpbp::{bech32, bech32::Blob, id};
use lnpbp_identity::{
    EcAlgo, IdentityCert, IdentitySigner, SigCert, VerifyError,
};
use serde::Serialize;
use strict_encoding::{StrictDecode, StrictEncode};

#[derive(Parser, Clone, Debug)]
#[clap(
    name = "lnpbp",
    bin_name = "lnpbp",
    author,
    version,
    about = "Command-line tool for working with LNP/BP stack"
)]
pub struct Opts {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Command {
    /// Commands for working with LNP/BP identities
    #[clap(subcommand)]
    Identity(IdentityCommand),

    /// Commands for converting data between encodings
    Convert {
        /// Formatting of the input data
        #[clap(short = 'f', long, default_value = "bech32")]
        from: Format,

        /// Formatting for the output
        #[clap(short = 't', long = "to", default_value = "yaml")]
        into: Format,

        /// Original data string
        #[clap(short, long, conflicts_with = "file")]
        data: Option<String>,

        /// File with the source data. If no `--data` option is given reads
        /// the data from STDIN
        #[clap()]
        input_file: Option<PathBuf>,

        /// File to store the results of the conversion. Defaults to STDOUT
        #[clap()]
        output_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum IdentityCommand {
    /// Generate a new identity, saving it to the file
    Create {
        /// Curve algorithm to use foe the new identity
        #[clap(short, long, default_value = "bip340")]
        algo: id::EcAlgo,

        /// File to store the identity in
        #[clap()]
        file: PathBuf,
    },

    /// Read info about the identity from the file
    Info {
        /// File containing identity information
        #[clap()]
        file: PathBuf,
    },

    /// Sign a message, a file or data read from STDIN
    Sign {
        /// File containing identity information
        #[clap()]
        identity_file: PathBuf,

        /// Message to sign
        #[clap(short, long)]
        message: Option<String>,

        /// File to sign
        #[clap(conflicts_with = "message")]
        message_file: Option<PathBuf>,
    },

    /// Verify an identity certificate and optionally a signature against a
    /// file, message or data read from STDIN
    Verify {
        /// An identity certificate to use
        #[clap()]
        cert: IdentityCert,

        /// A signature to verify
        #[clap()]
        sig: SigCert,

        /// Message to verify the signature
        #[clap(short, long = "msg")]
        message: Option<String>,

        /// File to verify the signature
        #[clap(conflicts_with = "message")]
        message_file: Option<PathBuf>,
    },

    /// Encrypt a message
    Encrypt {
        /// Use ASCII armoring
        #[clap(short, long = "ascii")]
        armor: bool,

        /// File containing local information
        #[clap()]
        identity_file: PathBuf,

        /// An identity of the receiver
        #[clap()]
        cert: IdentityCert,

        /// Message to encrypt
        #[clap(short, long = "msg", conflicts_with = "file")]
        message: Option<String>,

        /// File to encrypt
        #[clap()]
        src_file: Option<PathBuf>,

        /// Destination file to save the encrypted data to
        #[clap()]
        dst_file: Option<PathBuf>,
    },

    /// Decrypt a previously encrypted message
    Decrypt {
        /// The input data are ASCII armored
        #[clap(short, long = "ascii")]
        armor: bool,

        /// File containing local information
        #[clap()]
        identity_file: PathBuf,

        /// An identity of the receiver
        #[clap()]
        cert: IdentityCert,

        /// Message to decrypt
        #[clap(short, long = "msg", conflicts_with = "file")]
        message: Option<String>,

        /// File to decrypt
        #[clap()]
        src_file: Option<PathBuf>,

        /// Destination file to save the decrypted data to
        #[clap()]
        dst_file: Option<PathBuf>,
    },
}

#[derive(
    ArgEnum, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display
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
            "hex" | "base32" => Format::Hexadecimal,
            "raw" | "bin" | "binary" => Format::Raw,
            "rust" => Format::Rust,
            other => return Err(format!("Unknown format: {}", other)),
        })
    }
}

#[derive(Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Io(io::Error),

    #[from]
    Utf8(FromUtf8Error),

    #[display("incorrect hex string due to {0}")]
    #[from]
    Hex(hex::Error),

    #[display("incorrect bech32(m) string due to {0}")]
    #[from]
    Bech32(bech32::Error),

    #[display("incorrect base58 string")]
    #[from]
    Base58(FromBase58Error),

    #[display("incorrect base64 string due to {0}")]
    #[from]
    Base64(base64::DecodeError),

    #[display("incorrect JSON encoding. Details: {0}")]
    #[from]
    Json(serde_json::Error),

    #[display("incorrect YAML encoding. Details: {0}")]
    #[from]
    Yaml(serde_yaml::Error),

    #[display("incorrect encoding of the binary data. Details: {0}")]
    #[from]
    StrictEncoding(strict_encoding::Error),

    #[display("can't read data from {0} format")]
    UnsupportedFormat(Format),

    #[from]
    Signature(VerifyError),
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

fn input_read<T>(data: Vec<u8>, format: Format) -> Result<T, Error>
where
    T: From<Vec<u8>> + FromStr + for<'de> serde::Deserialize<'de>,
    Error: From<<T as FromStr>::Err>,
{
    match format {
        Format::Base64 => return Ok(base64::decode(&data).map(T::from)?),
        Format::Raw => return Ok(T::from(data)),
        _ => {}
    }

    let s = &String::from_utf8(data)?;
    Ok(match format {
        Format::Bech32 => T::from_str(s)?,
        Format::Base58 => T::from(s.from_base58()?),
        Format::Yaml => serde_yaml::from_str(s)?,
        Format::Json => serde_json::from_str(s)?,
        Format::Hexadecimal => T::from(Vec::<u8>::from_hex(s)?),
        _ => return Err(Error::UnsupportedFormat(format)),
    })
}

fn output_write<T>(
    mut f: impl Write,
    data: T,
    format: Format,
) -> Result<(), Error>
where
    T: AsRef<[u8]> + Debug + Display + Serialize,
{
    match format {
        Format::Debug => write!(f, "{:#?}", data),
        Format::Bech32 => write!(f, "{}", data),
        Format::Base58 => write!(f, "{}", data.as_ref().to_base58()),
        Format::Base64 => write!(f, "{}", base64::encode(data.as_ref())),
        Format::Yaml => write!(f, "{}", serde_yaml::to_string(data.as_ref())?),
        Format::Json => write!(f, "{}", serde_json::to_string(data.as_ref())?),
        Format::Hexadecimal => write!(f, "{}", data.as_ref().to_hex()),
        Format::Rust => write!(f, "{:#04X?}", data.as_ref()),
        Format::Raw => f.write(data.as_ref()).map(|_| ()),
    }
    .map_err(Error::from)
}

fn file_str_or_stdin(
    file: Option<PathBuf>,
    msg: Option<String>,
) -> Result<Box<dyn Read>, io::Error> {
    Ok(match (file, msg) {
        (Some(path), None) => {
            let fd = fs::File::open(path)?;
            Box::new(fd)
        }
        (None, Some(msg)) => {
            let cursor = io::Cursor::new(msg.into_bytes());
            let reader = io::BufReader::new(cursor);
            Box::new(reader)
        }
        (None, None) => {
            let fd = io::stdin();
            Box::new(fd)
        }
        (Some(_), Some(_)) => unreachable!("clap broken"),
    })
}

fn file_or_stdout(file: Option<PathBuf>) -> Result<Box<dyn Write>, io::Error> {
    Ok(match file {
        Some(path) => {
            let fd = fs::File::create(path)?;
            Box::new(fd)
        }
        None => {
            let fd = io::stdout();
            Box::new(fd)
        }
    })
}

fn main() -> Result<(), Error> {
    let opts = Opts::parse();

    match opts.command {
        Command::Identity(IdentityCommand::Create { algo, file }) => {
            if algo != EcAlgo::Bip340 {
                todo!("other than Secp256k1 BIP340 algorithms")
            }
            let id = IdentitySigner::new_bip340();
            let fd = fs::File::create(file)?;
            let mut perms = fd.metadata()?.permissions();
            perms.set_mode(0o600);
            fd.set_permissions(perms)?;
            id.strict_encode(fd)?;
            println!("{}", id.cert);
            println!("{:?}", id.cert);
        }
        Command::Identity(IdentityCommand::Info { file }) => {
            let fd = fs::File::open(file)?;
            let id = IdentitySigner::strict_decode(fd)?;
            println!("{}", id.cert);
            println!("{:?}", id.cert);
        }
        Command::Identity(IdentityCommand::Sign {
            identity_file,
            message,
            message_file,
        }) => {
            let fd = fs::File::open(identity_file)?;
            let id = IdentitySigner::strict_decode(fd)?;
            let input = file_str_or_stdin(message_file, message)?;
            let sig = id.sign_stream(input)?;
            println!("{}", sig);
        }
        Command::Identity(IdentityCommand::Verify {
            cert,
            sig,
            message,
            message_file,
        }) => {
            let mut input = file_str_or_stdin(message_file, message)?;
            let mut data = vec![];
            input.read_to_end(&mut data)?;
            sig.verify(&cert, data)?;
            println!("{}", "Signature is valid".green());
        }
        Command::Identity(_) => todo!("elgamal encryption support"),
        Command::Convert {
            data,
            from,
            into,
            input_file,
            output_file,
        } => {
            let mut input = file_str_or_stdin(input_file, data)?;
            let mut data = vec![];
            input.read_to_end(&mut data)?;
            let data: Blob = input_read(data, from)?;
            output_write(file_or_stdout(output_file)?, data, into)?;
        }
    }

    Ok(())
}
