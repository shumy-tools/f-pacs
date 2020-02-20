#![forbid(unsafe_code)]
#![allow(dead_code)]

use rand_os::OsRng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};

pub mod shares;
pub mod signatures;

pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

pub fn rnd_scalar() -> Scalar {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Scalar::random(&mut csprng)
}

pub struct KeyPair {
    pub s: Scalar,
    pub key: RistrettoPoint
}

impl KeyPair {
    pub fn new() -> Self {
        let s = rnd_scalar();
        Self { s, key: s * &G }
    }
}


pub trait KeyEncoder {
    fn encode(&self) -> String;
}

pub trait HardKeyDecoder<T> {
    fn decode(&self) -> T;
}

impl KeyEncoder for CompressedRistretto {
    fn encode(&self) -> String {
        base64::encode(self.as_bytes())
    }
}

impl KeyEncoder for RistrettoPoint {
    fn encode(&self) -> String {
        base64::encode(self.compress().as_bytes())
    }
}

impl KeyEncoder for Scalar {
    fn encode(&self) -> String {
        base64::encode(self.as_bytes())
    }
}

impl HardKeyDecoder<CompressedRistretto> for String {
    fn decode(&self) -> CompressedRistretto {
        let data = base64::decode(self.as_str()).expect("Unable to decode base58 input!");
        CompressedRistretto::from_slice(&data)
    }
}

impl HardKeyDecoder<RistrettoPoint> for String {
    fn decode(&self) -> RistrettoPoint {
        let data = base64::decode(self.as_str()).expect("Unable to decode base58 input!");
        let point = CompressedRistretto::from_slice(&data);
        point.decompress().expect("Unable to decompress RistrettoPoint!")
    }
}

impl HardKeyDecoder<Scalar> for String {
    fn decode(&self) -> Scalar {
        let data = base64::decode(self.as_str()).expect("Unable to decode base58 input!");
        let mut bytes: [u8; 32] = Default::default();
        bytes.copy_from_slice(&data[0..32]);

        Scalar::from_canonical_bytes(bytes).expect("Unable to decode Scalar!")
    }
}