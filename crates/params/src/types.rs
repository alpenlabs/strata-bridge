//! Types for the bridge parameters.

use serde::{Deserialize, Serialize};

use crate::errors::TagError;

/// Default tag size in bytes.
pub const TAG_SIZE: usize = 4;

/// Wrapper around a 4-byte tag (magic bytes) used to identify relevant bitcoin transactions.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Tag([u8; TAG_SIZE]);

impl Tag {
    /// Creates a new Tag from a byte array.
    pub const fn new(bytes: [u8; TAG_SIZE]) -> Self {
        Tag(bytes)
    }

    /// Returns the tag as a byte slice.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the tag as a byte array.
    pub const fn as_array(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }

    /// Returns the tag size in bytes.
    pub const fn size() -> usize {
        TAG_SIZE
    }

    /// Returns true if the tag contains all zero bytes.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Returns the length of the tag in bytes (always 4).
    pub const fn len(&self) -> usize {
        TAG_SIZE
    }
}

impl TryFrom<Vec<u8>> for Tag {
    type Error = TagError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() != TAG_SIZE {
            return Err(TagError::InvalidSize(bytes.len()));
        }
        let array: [u8; TAG_SIZE] = bytes.try_into().map_err(|_| TagError::ConversionFailed)?;
        Ok(Tag(array))
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = TagError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != TAG_SIZE {
            return Err(TagError::InvalidSize(bytes.len()));
        }
        let mut array = [0u8; TAG_SIZE];
        array.copy_from_slice(bytes);
        Ok(Tag(array))
    }
}

impl TryFrom<String> for Tag {
    type Error = TagError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_bytes().try_into()
    }
}

impl TryFrom<&str> for Tag {
    type Error = TagError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.as_bytes().try_into()
    }
}

impl From<Tag> for Vec<u8> {
    fn from(tag: Tag) -> Self {
        tag.0.to_vec()
    }
}

impl From<&Tag> for Vec<u8> {
    fn from(tag: &Tag) -> Self {
        tag.0.to_vec()
    }
}

impl From<Tag> for [u8; TAG_SIZE] {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

impl From<&Tag> for [u8; TAG_SIZE] {
    fn from(tag: &Tag) -> Self {
        tag.0
    }
}

impl From<Tag> for String {
    fn from(tag: Tag) -> Self {
        // Convert bytes to string, handling non-UTF8 bytes gracefully
        String::from_utf8_lossy(&tag.0).into_owned()
    }
}

impl From<&Tag> for String {
    fn from(tag: &Tag) -> Self {
        String::from_utf8_lossy(&tag.0).into_owned()
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_empty() {
        // Empty tag with all zeros
        let empty_tag = Tag::new([0, 0, 0, 0]);
        assert!(empty_tag.is_empty());

        // Non-empty tag
        let non_empty_tag = Tag::new([1, 2, 3, 4]);
        assert!(!non_empty_tag.is_empty());

        // Tag with some zeros but not all
        let partial_zero_tag = Tag::new([0, 1, 0, 0]);
        assert!(!partial_zero_tag.is_empty());
    }

    #[test]
    fn tag_len() {
        let tag = Tag::new([1, 2, 3, 4]);
        assert_eq!(tag.len(), TAG_SIZE);
        assert_eq!(tag.len(), 4);

        // Length should be constant regardless of content
        let empty_tag = Tag::new([0, 0, 0, 0]);
        assert_eq!(empty_tag.len(), TAG_SIZE);
        assert_eq!(empty_tag.len(), 4);
    }

    #[test]
    fn tag_from_str() {
        let tag = Tag::try_from("alpn").unwrap();
        assert_eq!(tag.len(), 4);
        assert!(!tag.is_empty());
        assert_eq!(tag.as_bytes(), b"alpn");
    }
}
