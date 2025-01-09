use rkyv::{
    api::high::{to_bytes_in, HighSerializer},
    rancor,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    Archive, Deserialize, Serialize,
};

trait WireMessageMarker:
    for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}

#[derive(Archive, Serialize, Deserialize)]
pub enum ServerMessage {
    Bob,
}

impl WireMessageMarker for ServerMessage {}

#[derive(Archive, Serialize, Deserialize)]
pub enum ClientMessage {
    Bob,
}

impl WireMessageMarker for ClientMessage {}

pub trait WireMessage {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error>;
}

// ignore, probably will just directly write to the connection instead of this
impl<T: WireMessageMarker> WireMessage for T {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error> {
        let mut aligned_buf = AlignedVec::new();
        // write a default length
        aligned_buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut aligned_buf = to_bytes_in(self, aligned_buf)?;
        let len = aligned_buf.len() - 4;
        debug_assert!(len <= u32::MAX as usize);
        let len_as_le_bytes = (len as u32).to_le_bytes();
        for i in 0..4 {
            aligned_buf[i] = len_as_le_bytes[i]
        }
        Ok(aligned_buf)
    }
}
