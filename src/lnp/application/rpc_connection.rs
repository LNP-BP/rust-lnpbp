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

use std::fmt::{Debug, Display};

use crate::lnp::presentation::{self, message};
use crate::lnp::session::Connect;
use crate::lnp::transport::Connection;
use crate::lnp::{LocalNode, ToNodeEndpoint};

/// Marker trait for LNP RPC requests
pub trait Request:
    Debug + Display + message::TypedEnum + presentation::CreateUnmarshaller
{
}

/// Marker trait for LNP RPC replies
pub trait Reply:
    Debug + Display + message::TypedEnum + presentation::CreateUnmarshaller
{
}

/// RPC API pair, connecting [`Request`] type with [`Reply`]
pub trait Api {
    /// Requests supported by RPC API
    type Request: Request;

    /// Replies supported by RPC API
    type Reply: Reply;
}

pub struct RpcConnection<A>
where
    A: Api,
{
    api: A,
    session: Box<dyn Connection>,
}

impl<A> RpcConnection<A>
where
    A: Api,
{
    pub fn new(
        api: A,
        remote: impl ToNodeEndpoint,
        local: &LocalNode,
        default_port: u16,
    ) -> Result<Self, presentation::Error> {
        let endpoint = remote
            .to_node_endpoint(default_port)
            .ok_or(presentation::Error::InvalidEndpoint)?;
        let session = endpoint.connect(local)?;
        Ok(Self { api, session })
    }
}