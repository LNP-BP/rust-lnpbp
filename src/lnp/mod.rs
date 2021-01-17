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

//! Module that systematizes all Lightning network-related APIs from the
//! `lightning` library into layered & modular design

pub mod application;

pub use application::payment::{ChannelId, TempChannelId};
pub use application::{
    channel, factories, message, FeatureContext, FeatureFlag, Features,
    Messages, OnionPacket, PeerConnection, PeerReceiver, PeerSender,
    RecvMessage, RpcConnection, SendMessage, LNPWP_UNMARSHALLER,
};

pub const LIGHTNING_P2P_DEFAULT_PORT: u16 = 9735;
