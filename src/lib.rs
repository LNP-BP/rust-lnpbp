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

#![doc = include_str!("../README.md")]

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]
// TODO #184: when we will be ready for the release #![deny(missing_docs)]

pub extern crate lnpbp_bech32 as bech32;
pub extern crate lnpbp_chain as chain;
#[cfg(feature = "elgamal")]
pub extern crate lnpbp_elgamal as elgamal;

pub extern crate client_side_validation;

#[cfg(test)]
pub mod test {
    use bitcoin::secp256k1;
    use wallet::SECP256K1;

    pub fn gen_secp_pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let mut sk = [0; 32];

        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            ret.push(secp256k1::PublicKey::from_secret_key(
                &SECP256K1,
                &secp256k1::SecretKey::from_slice(&sk[..]).unwrap(),
            ));
        }
        ret
    }

    pub fn gen_bitcoin_pubkeys(
        n: usize,
        compressed: bool,
    ) -> Vec<bitcoin::PublicKey> {
        gen_secp_pubkeys(n)
            .into_iter()
            .map(|key| bitcoin::PublicKey { key, compressed })
            .collect()
    }
}
