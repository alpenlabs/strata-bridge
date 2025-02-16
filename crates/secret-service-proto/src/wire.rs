use rkyv::{
    api::high::{to_bytes_in, HighSerializer},
    rancor,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    Archive, Deserialize, Serialize,
};

use crate::v1;

trait WireMessageMarker:
    for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}

pub trait WireMessage {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error>;
}

pub type LengthUint = u16;

#[repr(u8)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum VersionedClientMessage {
    V1(v1::wire::ClientMessage),
}

impl WireMessageMarker for VersionedClientMessage {}

#[repr(u8)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum VersionedServerMessage {
    V1(v1::wire::ServerMessage),
}

impl WireMessageMarker for VersionedServerMessage {}

impl<T: WireMessageMarker> WireMessage for T {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error> {
        let mut aligned_buf = AlignedVec::new();
        aligned_buf.extend_from_slice(&LengthUint::MAX.to_le_bytes());
        let mut aligned_buf = to_bytes_in(self, aligned_buf)?;
        let len = aligned_buf.len() - size_of::<LengthUint>();
        assert!(len <= LengthUint::MAX as usize);
        (len as LengthUint)
            .to_le_bytes()
            .into_iter()
            .enumerate()
            .for_each(|byte| {
                aligned_buf[byte.0] = byte.1;
            });
        Ok(aligned_buf)
    }
}
