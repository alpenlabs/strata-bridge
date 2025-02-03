use rkyv::{Archive, Deserialize, Serialize};
use secp256k1::ffi::CPtr;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Archive, Serialize, Deserialize)]
#[rkyv(remote = secp::Point)]
pub struct Point {
    #[rkyv(getter = point_inner_getter, with = PublicKey)]
    inner: secp256k1::PublicKey,
}

fn point_inner_getter(p: &secp::Point) -> secp256k1::PublicKey {
    p.clone().into()
}

impl From<Point> for secp::Point {
    fn from(value: Point) -> Self {
        Self::from(value.inner)
    }
}

impl From<secp::Point> for Point {
    fn from(value: secp::Point) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

#[derive(
    Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Archive, Serialize, Deserialize,
)]
#[rkyv(remote = secp256k1::PublicKey)]
pub struct PublicKey(
    #[rkyv(getter = public_key_getter, with = FFIPublicKey)] secp256k1::ffi::PublicKey,
);

fn public_key_getter(p: &secp256k1::PublicKey) -> secp256k1::ffi::PublicKey {
    unsafe { *p.as_c_ptr().clone() }
}

impl From<PublicKey> for secp256k1::PublicKey {
    fn from(value: PublicKey) -> Self {
        value.0.into()
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(value: secp256k1::PublicKey) -> Self {
        Self(public_key_getter(&value))
    }
}

#[derive(Copy, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = secp256k1::ffi::PublicKey)]
pub struct FFIPublicKey(#[rkyv(getter = ffi_public_key_getter)] [u8; 64]);

fn ffi_public_key_getter(p: &secp256k1::ffi::PublicKey) -> [u8; 64] {
    p.underlying_bytes()
}

impl From<FFIPublicKey> for secp256k1::ffi::PublicKey {
    fn from(value: FFIPublicKey) -> Self {
        unsafe { Self::from_array_unchecked(value.0) }
    }
}

impl From<secp256k1::ffi::PublicKey> for FFIPublicKey {
    fn from(value: secp256k1::ffi::PublicKey) -> Self {
        Self(value.underlying_bytes())
    }
}

#[derive(Copy, Clone, Debug, Archive, Serialize, Deserialize)]
#[rkyv(remote = subtle::Choice)]
pub struct Choice(#[rkyv(getter = choice_getter)] u8);

fn choice_getter(c: &subtle::Choice) -> u8 {
    c.unwrap_u8()
}

impl From<Choice> for subtle::Choice {
    fn from(value: Choice) -> Self {
        Self::from(value.0)
    }
}

impl From<subtle::Choice> for Choice {
    fn from(value: subtle::Choice) -> Self {
        Self(value.unwrap_u8())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Archive, Serialize, Deserialize,
)]
#[rkyv(remote = secp::MaybePoint)]
pub enum MaybePoint {
    Infinity,
    Valid(#[rkyv(with = Point)] secp::Point),
}

impl From<MaybePoint> for secp::MaybePoint {
    fn from(value: MaybePoint) -> Self {
        match value {
            MaybePoint::Infinity => Self::Infinity,
            MaybePoint::Valid(p) => Self::Valid(p),
        }
    }
}

impl From<secp::MaybePoint> for MaybePoint {
    fn from(value: secp::MaybePoint) -> Self {
        match value {
            secp::MaybePoint::Infinity => Self::Infinity,
            secp::MaybePoint::Valid(p) => Self::Valid(p.into()),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Archive, Serialize, Deserialize)]
#[rkyv(remote = secp::MaybeScalar)]
pub enum MaybeScalar {
    Zero,
    Valid(#[rkyv(with = Scalar)] secp::Scalar),
}

impl From<MaybeScalar> for secp::MaybeScalar {
    fn from(value: MaybeScalar) -> Self {
        match value {
            MaybeScalar::Zero => Self::Zero,
            MaybeScalar::Valid(s) => Self::Valid(s),
        }
    }
}

impl From<secp::MaybeScalar> for MaybeScalar {
    fn from(value: secp::MaybeScalar) -> Self {
        match value {
            secp::MaybeScalar::Zero => Self::Zero,
            secp::MaybeScalar::Valid(s) => Self::Valid(s),
        }
    }
}

#[derive(Copy, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = secp::Scalar)]
pub struct Scalar {
    #[rkyv(with = SecretKey, getter = scalar_getter)]
    inner: secp256k1::SecretKey,
}

fn scalar_getter(s: &secp::Scalar) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&s.serialize()).unwrap()
}

impl From<Scalar> for secp::Scalar {
    fn from(value: Scalar) -> Self {
        Self::from(value.inner)
    }
}

impl From<secp::Scalar> for Scalar {
    fn from(value: secp::Scalar) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

#[derive(Copy, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = secp256k1::SecretKey)]
pub struct SecretKey(
    #[rkyv(getter = secret_key_getter)] [u8; secp256k1::constants::SECRET_KEY_SIZE],
);

fn secret_key_getter(sk: &secp256k1::SecretKey) -> [u8; secp256k1::constants::SECRET_KEY_SIZE] {
    sk.secret_bytes()
}

impl From<SecretKey> for secp256k1::SecretKey {
    fn from(value: SecretKey) -> Self {
        Self::from_slice(&value.0).unwrap()
    }
}

impl From<secp256k1::SecretKey> for SecretKey {
    fn from(value: secp256k1::SecretKey) -> Self {
        Self(value.secret_bytes())
    }
}
