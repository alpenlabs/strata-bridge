//! WOTS variable-length public keys.

use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use bitcoin::hex::DisplayHex;
#[cfg(feature = "proptest")]
use proptest_derive::Arbitrary;
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{Serialize, SerializeSeq, Serializer},
    Deserialize, Deserializer,
};

/// A single Winternitz One-Time Signature (WOTS) hash value.
pub const WOTS_SINGLE: usize = 20;

/// The number of bits in an individual WOTS digit.
// WARNING(proofofkeags): MUST BE A FACTOR OF 8 WITH CURRENT IMPLEMENTATION (1,2,4,8)
pub(crate) const WOTS_DIGIT_WIDTH: usize = 4;

/// The number of WOTS digits needed to commit a byte.
pub(crate) const WOTS_DIGITS_PER_BYTE: usize = 8 / WOTS_DIGIT_WIDTH;

/// The maximum number a WOTS digit can hold.
#[allow(unfulfilled_lint_expectations)]
#[expect(dead_code)]
pub(crate) const WOTS_MAX_DIGIT: usize = (2 << WOTS_DIGIT_WIDTH) - 1;

/// The number of WOTS digits required to represent a message for a given message length.
#[allow(unfulfilled_lint_expectations)]
#[expect(dead_code)]
pub(crate) const fn wots_msg_digits(msg_len_bytes: usize) -> usize {
    WOTS_DIGITS_PER_BYTE * msg_len_bytes
}

/// The number of WOTS digits required to sign the checksum for a given message length.
///
/// The checksum of a WOTS commitment is the sum of the digit values themselves which is then
/// encoded as a base256 integer. That integer is then signed using the same WOTS scheme.
#[allow(unfulfilled_lint_expectations)]
#[expect(dead_code)]
pub(crate) const fn wots_checksum_digits(msg_len_bytes: usize) -> usize {
    let max_checksum = wots_msg_digits(msg_len_bytes) * WOTS_MAX_DIGIT;

    // Compute how many bytes we need to represent the checksum itself
    let mut exp = 1;
    loop {
        if 256u64.strict_pow(exp) > max_checksum as u64 {
            break;
        } else {
            exp += 1;
        }
    }
    let num_checksum_bytes = exp as usize;

    // Multiply the checksum bytes by the digits per byte value.
    WOTS_DIGITS_PER_BYTE * num_checksum_bytes
}

/// The total number of WOTS digit keys
#[allow(unfulfilled_lint_expectations)]
#[expect(dead_code)]
pub(crate) const fn wots_total_digits(msg_len_bytes: usize) -> usize {
    wots_msg_digits(msg_len_bytes) + wots_checksum_digits(msg_len_bytes)
}

/// A variable-length Winternitz One-Time Signature (WOTS) public key.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
pub struct WotsPublicKey<const MSG_LEN_BYTES: usize>(pub [WotsSingleBytes; MSG_LEN_BYTES])
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized;
/// Required to work around some rkyv_derive limitations.
type WotsSingleBytes = [u8; WOTS_SINGLE];

/// 128-bit Winternitz One-Time Signature (WOTS) public key.
pub type Wots128PublicKey = WotsPublicKey<36>;

/// 160-bit Winternitz One-Time Signature (WOTS) public key.
pub type Wots160PublicKey = WotsPublicKey<44>;

/// 256-bit Winternitz One-Time Signature (WOTS) public key.
pub type Wots256PublicKey = WotsPublicKey<68>;

impl<const MSG_LEN_BYTES: usize> fmt::Debug for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let first_bytes = &self.0[0];
        write!(f, "WotsPublicKey({first_bytes:?})")
    }
}

impl<const MSG_LEN_BYTES: usize> fmt::Display for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let first_bytes = self.0[0].to_lower_hex_string();
        write!(f, "WotsPublicKey({first_bytes})")
    }
}

impl<const MSG_LEN_BYTES: usize> WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    /// The size of this WOTS public key in bytes.
    pub const SIZE: usize = MSG_LEN_BYTES;

    /// Creates a new WOTS public key from a byte array.
    pub const fn new(bytes: [[u8; WOTS_SINGLE]; MSG_LEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Converts the public key to a byte array.
    pub const fn to_bytes(self) -> [[u8; WOTS_SINGLE]; MSG_LEN_BYTES] {
        self.0
    }

    /// Converts the public key to a flattened byte array.
    pub fn to_flattened_bytes(self) -> Vec<u8> {
        // Changed return type to Vec<u8>
        let mut bytes = Vec::with_capacity(WOTS_SINGLE * MSG_LEN_BYTES);
        for byte_array in &self.0 {
            bytes.extend_from_slice(byte_array);
        }
        bytes
    }

    /// Creates the public key from a flattened byte array.
    ///
    /// If you already have a structured `[[u8; 20]; MSG_LEN]` then you should use
    /// [`WotsPublicKey::new`].
    ///
    /// # Panics
    ///
    /// Panics if the byte array is not of proper length.
    pub fn from_flattened_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            WOTS_SINGLE * MSG_LEN_BYTES,
            "Invalid byte array length"
        );

        let mut key = [[0u8; WOTS_SINGLE]; MSG_LEN_BYTES];
        for (i, byte_array) in key.iter_mut().enumerate() {
            byte_array.copy_from_slice(&bytes[i * WOTS_SINGLE..(i + 1) * WOTS_SINGLE]);
        }
        Self(key)
    }
}

impl<const MSG_LEN_BYTES: usize> Deref for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    type Target = [[u8; WOTS_SINGLE]; MSG_LEN_BYTES];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const MSG_LEN_BYTES: usize> DerefMut for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Custom Serialization for WotsPublicKey
impl<const MSG_LEN_BYTES: usize> Serialize for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut seq = serializer.serialize_seq(Some(2 * MSG_LEN_BYTES + 4))?;
            for byte_array in &self.0 {
                seq.serialize_element(byte_array)?;
            }
            seq.end()
        } else {
            serializer.serialize_bytes(&self.to_flattened_bytes())
        }
    }
}

// Custom Deserialization for WotsPublicKey
impl<'de, const MSG_LEN_BYTES: usize> Deserialize<'de> for WotsPublicKey<MSG_LEN_BYTES>
where
    [(); MSG_LEN_BYTES]: Sized,
    [(); WOTS_SINGLE * MSG_LEN_BYTES]: Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WotsPublicKeyVisitor<const M: usize>;

        impl<'de, const M: usize> Visitor<'de> for WotsPublicKeyVisitor<M>
        where
            [(); M]: Sized,
            [(); WOTS_SINGLE * M]: Sized,
        {
            type Value = WotsPublicKey<M>;

            #[expect(elided_lifetimes_in_paths)]
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!("a WotsPublicKey with {} bytes", WOTS_SINGLE * M))
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if bytes.len() != WOTS_SINGLE * M {
                    return Err(E::invalid_length(bytes.len(), &self));
                }

                let mut array = [[0u8; WOTS_SINGLE]; M];
                for (i, chunk) in bytes.chunks(WOTS_SINGLE).enumerate() {
                    array[i].copy_from_slice(chunk);
                }
                Ok(WotsPublicKey(array))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
                [(); WOTS_SINGLE * M]: Sized,
            {
                let mut array = [[0u8; WOTS_SINGLE]; M];
                for (i, item) in array.iter_mut().enumerate() {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<[u8; WOTS_SINGLE]>()?.is_some() {
                    return Err(de::Error::invalid_length(2 * M + 5, &self));
                }
                Ok(WotsPublicKey(array))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_seq(WotsPublicKeyVisitor::<MSG_LEN_BYTES>)
        } else {
            deserializer.deserialize_bytes(WotsPublicKeyVisitor::<MSG_LEN_BYTES>)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "proptest")]
    use proptest::prelude::*;

    use super::*;

    // Sanity checks for constants
    #[test]
    fn sanity_check_constants() {
        assert_eq!(WOTS_SINGLE, 20);
        assert_eq!(WOTS_DIGIT_WIDTH, 4);
        assert_eq!(wots_msg_digits(32), 64);
        assert_eq!(wots_msg_digits(20), 40);
        assert_eq!(wots_checksum_digits(32), 4);
        assert_eq!(wots_checksum_digits(20), 4);
    }

    #[test]
    fn flattened_bytes_roundtrip() {
        let key128 = Wots128PublicKey::new([[1u8; WOTS_SINGLE]; 36]); // 2 * 16 + 4
        let key160 = Wots160PublicKey::new([[1u8; WOTS_SINGLE]; 44]); // 2 * 20 + 4
        let key256 = Wots256PublicKey::new([[1u8; WOTS_SINGLE]; 68]); // 2 * 32 + 4

        // Test flattened bytes roundtrip
        let flattened128 = key128.to_flattened_bytes();
        let flattened160 = key160.to_flattened_bytes();
        let flattened256 = key256.to_flattened_bytes();

        let deserialized128 = Wots128PublicKey::from_flattened_bytes(&flattened128);
        let deserialized160 = Wots160PublicKey::from_flattened_bytes(&flattened160);
        let deserialized256 = Wots256PublicKey::from_flattened_bytes(&flattened256);

        assert_eq!(key128, deserialized128);
        assert_eq!(key160, deserialized160);
        assert_eq!(key256, deserialized256);
    }

    #[test]
    fn json_serialization() {
        let key128 = Wots128PublicKey::new([[1u8; WOTS_SINGLE]; 36]); // 2 * 16 + 4
        let key160 = Wots160PublicKey::new([[1u8; WOTS_SINGLE]; 44]); // 2 * 20 + 4
        let key256 = Wots256PublicKey::new([[1u8; WOTS_SINGLE]; 68]); // 2 * 32 + 4

        // Test JSON serialization
        let serialized128 = serde_json::to_string(&key128).unwrap();
        let serialized160 = serde_json::to_string(&key160).unwrap();
        let serialized256 = serde_json::to_string(&key256).unwrap();
        let deserialized128: Wots128PublicKey = serde_json::from_str(&serialized128).unwrap();
        let deserialized160: Wots160PublicKey = serde_json::from_str(&serialized160).unwrap();
        let deserialized256: Wots256PublicKey = serde_json::from_str(&serialized256).unwrap();

        assert_eq!(key128, deserialized128);
        assert_eq!(key160, deserialized160);
        assert_eq!(key256, deserialized256);
    }

    #[test]
    fn bincode_serialization() {
        let key128 = Wots128PublicKey::new([[1u8; WOTS_SINGLE]; 36]); // 2 * 16 + 4
        let key160 = Wots160PublicKey::new([[1u8; WOTS_SINGLE]; 44]); // 2 * 20 + 4
        let key256 = Wots256PublicKey::new([[1u8; WOTS_SINGLE]; 68]); // 2 * 32 + 4

        // Test bincode serialization
        let serialized128 = bincode::serialize(&key128).unwrap();
        let deserialized128: Wots128PublicKey = bincode::deserialize(&serialized128).unwrap();

        let serialized160 = bincode::serialize(&key160).unwrap();
        let deserialized160: Wots160PublicKey = bincode::deserialize(&serialized160).unwrap();

        let serialized256 = bincode::serialize(&key256).unwrap();
        let deserialized256: Wots256PublicKey = bincode::deserialize(&serialized256).unwrap();

        assert_eq!(key128, deserialized128);
        assert_eq!(key160, deserialized160);
        assert_eq!(key256, deserialized256);
    }

    #[test]
    #[should_panic]
    fn deserialize_too_few_elements() {
        let json = "[[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]]"; // Only one array
        let _: Wots128PublicKey = serde_json::from_str(json).unwrap();
        let _: Wots160PublicKey = serde_json::from_str(json).unwrap();
        let _: Wots256PublicKey = serde_json::from_str(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_too_many_elements128() {
        // Create JSON string with 37 arrays
        let mut json = String::from("[");
        for i in 0..37 {
            json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            if i < 36 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots128PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_too_many_elements160() {
        // Create JSON string with 45 arrays
        let mut json = String::from("[");
        for i in 0..45 {
            json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            if i < 44 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots160PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_too_many_elements256() {
        // Create JSON string with 33 arrays
        let mut json = String::from("[");
        for i in 0..33 {
            json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            if i < 32 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots256PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_invalid_array_length36() {
        // Create JSON with one array having wrong length (19 instead of 20)
        let mut json = String::from("[");
        for i in 0..WotsPublicKey::<36>::SIZE {
            if i == 8 {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]"); // 19 elements
            } else {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            }
            if i < WotsPublicKey::<36>::SIZE - 1 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots160PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_invalid_array_length44() {
        // Create JSON with one array having wrong length (19 instead of 20)
        let mut json = String::from("[");
        for i in 0..WotsPublicKey::<44>::SIZE {
            if i == 14 {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]"); // 19 elements
            } else {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            }
            if i < WotsPublicKey::<44>::SIZE - 1 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots160PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    #[should_panic]
    fn deserialize_invalid_array_length256() {
        // Create JSON with one array having wrong length (19 instead of 20)
        let mut json = String::from("[");
        for i in 0..WotsPublicKey::<68>::SIZE {
            if i == 20 {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]"); // 19 elements
            } else {
                json.push_str("[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]");
            }
            if i < WotsPublicKey::<68>::SIZE - 1 {
                json.push(',');
            }
        }
        json.push(']');

        let _: Wots256PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[cfg(feature = "proptest")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        #[test]
        fn proptest_serde_json_roundtrip128(key: Wots128PublicKey) {
            let serialized = serde_json::to_string(&key).unwrap();
            let deserialized: Wots128PublicKey = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_serde_json_roundtrip160(key: Wots160PublicKey) {
            let serialized = serde_json::to_string(&key).unwrap();
            let deserialized: Wots160PublicKey = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_serde_json_roundtrip256(key: Wots256PublicKey) {
            let serialized = serde_json::to_string(&key).unwrap();
            let deserialized: Wots256PublicKey = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_bincode_roundtrip128(key: Wots128PublicKey) {
            let serialized = bincode::serialize(&key).unwrap();
            let deserialized: Wots128PublicKey = bincode::deserialize(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_bincode_roundtrip160(key: Wots160PublicKey) {
            let serialized = bincode::serialize(&key).unwrap();
            let deserialized: Wots160PublicKey = bincode::deserialize(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_bincode_roundtrip256(key: Wots256PublicKey) {
            let serialized = bincode::serialize(&key).unwrap();
            let deserialized: Wots256PublicKey = bincode::deserialize(&serialized).unwrap();
            prop_assert_eq!(key, deserialized);
        }

        #[test]
        fn proptest_deref_operations128(key: Wots128PublicKey) {
            let mut key_copy = key;

            // Test Deref
            prop_assert_eq!(&key.0, &*key);

            // Test DerefMut
            (*key_copy)[0] = [34u8; WOTS_SINGLE];
            prop_assert_eq!(key_copy.0[0], [34u8; WOTS_SINGLE]);
        }

        #[test]
        fn proptest_deref_operations160(key: Wots160PublicKey) {
            let mut key_copy = key;

            // Test Deref
            prop_assert_eq!(&key.0, &*key);

            // Test DerefMut
            (*key_copy)[0] = [42u8; WOTS_SINGLE];
            prop_assert_eq!(key_copy.0[0], [42u8; WOTS_SINGLE]);
        }

        #[test]
        fn proptest_deref_operations256(key: Wots256PublicKey) {
            let mut key_copy = key;

            // Test Deref
            prop_assert_eq!(&key.0, &*key);

            // Test DerefMut
            (*key_copy)[0] = [42u8; WOTS_SINGLE];
            prop_assert_eq!(key_copy.0[0], [42u8; WOTS_SINGLE]);
        }

        #[test]
        fn proptest_new_constructor128(bytes: [[u8; WOTS_SINGLE]; 36]) { // 2 * 18 + 4
            let key = Wots128PublicKey::new(bytes);
            prop_assert_eq!(key.0, bytes);
        }

        #[test]
        fn proptest_new_constructor160(bytes: [[u8; WOTS_SINGLE]; 44]) { // 2 * 20 + 4
            let key = Wots160PublicKey::new(bytes);
            prop_assert_eq!(key.0, bytes);
        }

        #[test]
        fn proptest_new_constructor256(bytes: [[u8; WOTS_SINGLE]; 68]) { // 2 * 32 + 4
            let key = Wots256PublicKey::new(bytes);
            prop_assert_eq!(key.0, bytes);
        }

        #[test]
        fn proptest_to_flattened_bytes128(key: Wots128PublicKey) {
            let flattened = key.to_flattened_bytes();

            // Verify the length is correct
            prop_assert_eq!(flattened.len(), WOTS_SINGLE * 36);

            // Verify each segment matches the original arrays
            for (i, original_array) in key.0.iter().enumerate() {
                let segment = &flattened[i * WOTS_SINGLE..(i + 1) * WOTS_SINGLE];
                prop_assert_eq!(segment, original_array.as_slice());
            }
        }

        #[test]
        fn proptest_to_flattened_bytes160(key: Wots160PublicKey) {
            let flattened = key.to_flattened_bytes();

            // Verify the length is correct
            prop_assert_eq!(flattened.len(), WOTS_SINGLE * 44);

            // Verify each segment matches the original arrays
            for (i, original_array) in key.0.iter().enumerate() {
                let segment = &flattened[i * WOTS_SINGLE..(i + 1) * WOTS_SINGLE];
                prop_assert_eq!(segment, original_array.as_slice());
            }
        }

        #[test]
        fn proptest_to_flattened_bytes256(key: Wots256PublicKey) {
            let flattened = key.to_flattened_bytes();

            // Verify the length is correct
            prop_assert_eq!(flattened.len(), WOTS_SINGLE * 68);

            // Verify each segment matches the original arrays
            for (i, original_array) in key.0.iter().enumerate() {
                let segment = &flattened[i * WOTS_SINGLE..(i + 1) * WOTS_SINGLE];
                prop_assert_eq!(segment, original_array.as_slice());
            }
        }
    }
}
