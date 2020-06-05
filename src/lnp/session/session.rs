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

use core::borrow::Borrow;

use super::{Decrypt, Encrypt, NodeLocator, Transcode};
use crate::lnp::session::NoEncryption;
use crate::lnp::transport::zmq::{ApiType as ZmqType, Connection, SocketLocator};
use crate::lnp::transport::{self, Bidirect, Error, Input, Output, Read, Write};
use crate::{AsAny, Bipolar};

pub trait SessionTrait: Bipolar + AsAny {}

type TranscodeFull = dyn Transcode<
    Encryptor = dyn Encrypt,
    Decryptor = dyn Decrypt<Error = dyn ::std::error::Error>,
>;

pub struct Session {
    transcoder: Arc<TranscodeFull>,
    stream: Arc<
        dyn Bidirect<Input = dyn Input<Reader = dyn Read>, Output = dyn Output<Writer = dyn Write>>,
    >,
}

pub struct Inbound {
    pub(self) decryptor: Arc<dyn Decrypt<Error = dyn ::std::error::Error>>,
    pub(self) input: Arc<dyn Input<Reader = dyn Read>>,
}

pub struct Outbound {
    pub(self) encryptor: Arc<dyn Encrypt>,
    pub(self) output: Arc<dyn Output<Writer = dyn Write>>,
}

impl<T, S> Session<T, S>
where
    T: Transcode,
    S: Bidirect,
{
    pub fn new(_node_locator: NodeLocator) -> Result<Self, Error> {
        unimplemented!()
    }

    pub fn new_zmq_unencrypted(
        zmq_type: ZmqType,
        context: &mut zmq::Context,
        remote: SocketLocator,
        local: Option<SocketLocator>,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: Arc::new(NoEncryption)
                as Arc<
                    dyn Transcode<
                        Encryptor = dyn Encrypt,
                        Decryptor = dyn Decrypt<Error = dyn ::std::error::Error>,
                    >,
                >,
            stream: Arc::new(Connection::new(zmq_type, context, remote, local)?),
        })
    }
}

impl Bipolar for Session {
    type Left = Inbound;
    type Right = Outbound;

    fn join(_left: Self::Left, _right: Self::Right) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        unimplemented!()
    }
}

impl<T, S> Session<T, S>
where
    T: Transcode,
    S: Bidirect,
    Error: From<T::Error>,
{
    pub fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.stream.reader();
        Ok(self.transcoder.decrypt(reader.read()?)?)
    }

    pub fn send_raw_message(&mut self, raw: impl Borrow<[u8]>) -> Result<usize, Error> {
        let writer = self.stream.writer();
        Ok(writer.write(self.transcoder.encrypt(raw))?)
    }
}
