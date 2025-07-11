//! Secret Service wire protocol

use rkyv::{
    api::high::HighSerializer, rancor, ser::allocator::ArenaHandle, to_bytes, util::AlignedVec,
    Archive, Deserialize, Serialize,
};

use crate::v2;

trait WireMessageMarker:
    for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}

/// A trait for serializing wire messages.
pub trait WireMessage {
    /// Serialize the wire message into an aligned vector using rkyv.
    fn serialize(&self) -> Result<([u8; 2], AlignedVec), rancor::Error>;
}

/// The length unit used for wire messages.
pub type LengthUint = u16;

/// The global data structure used for wire messages from a client.
#[repr(u8)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum VersionedClientMessage {
    /// Version 2 of the client message.
    V2(v2::wire::ClientMessage),
}

impl WireMessageMarker for VersionedClientMessage {}

/// The global data structure used for wire messages from a server.
#[repr(u8)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum VersionedServerMessage {
    /// Version 2 of the server message.
    V2(v2::wire::ServerMessage),
}

impl WireMessageMarker for VersionedServerMessage {}

impl<T: WireMessageMarker> WireMessage for T {
    fn serialize(&self) -> Result<([u8; 2], AlignedVec), rancor::Error> {
        to_bytes(self).map(|b| ((b.len() as LengthUint).to_le_bytes(), b))
    }
}
