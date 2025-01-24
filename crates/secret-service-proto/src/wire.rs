use rkyv::{Archive, Deserialize, Serialize};

use crate::v1;

#[repr(u8)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum VersionedClientMessage {
    V1(v1::wire::ClientMessage),
}
