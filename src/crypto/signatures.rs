use std::fmt::{Debug, Formatter};

use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::{Deserializer, Error};

use sha2::{Sha512, Digest};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint};

use crate::crypto::{G, KeyEncoder};

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize)]
struct SerializedSignature {
    pub sig: String
}

#[derive(Clone)]
pub struct Signature {
    pub encoded: String,
    pub c: Scalar,
    pub p: Scalar
}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(&self.encoded)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let ss = SerializedSignature { sig: self.encoded.clone() };
        ss.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let ss = SerializedSignature::deserialize(deserializer)?;

        let data = base64::decode(&ss.sig)
            .map_err(|_| Error::custom("Invalid base64 signature string!"))?;
        
        if data.len() != 64 {
            return Err(Error::custom("Incorrect signature lenght!"))
        }

        let mut c_bytes: [u8; 32] = Default::default();
        c_bytes.copy_from_slice(&data[0..32]);

        let mut p_bytes: [u8; 32] = Default::default();
        p_bytes.copy_from_slice(&data[32..64]);

        let c_scalar = Scalar::from_canonical_bytes(c_bytes)
            .ok_or_else(|| Error::custom("Invalid c scalar!"))?;
        
        let p_scalar = Scalar::from_canonical_bytes(p_bytes)
            .ok_or_else(|| Error::custom("Invalid p scalar!"))?;

        let obj = Signature { encoded: ss.sig, c: c_scalar, p: p_scalar };
        Ok(obj)
    }
}

impl Signature {
    #[allow(non_snake_case)]
    pub fn sign(s: &Scalar, key: &RistrettoPoint, data: &[Vec<u8>]) -> Self {
        let mut hasher = Sha512::new()
            .chain(s.as_bytes());
        
        for d in data {
            hasher.input(d);
        }

        let m = Scalar::from_hash(hasher); 
        let M = (m * G).compress();

        let mut hasher = Sha512::new()
            .chain(key.compress().as_bytes())
            .chain(M.as_bytes());
        
        for d in data {
            hasher.input(d);
        }

        let c = Scalar::from_hash(hasher);
        let p = m - c * s;

        let data: &[&[u8]] = &[c.as_bytes(), p.as_bytes()];
        let data = data.concat();

        Self { encoded: base64::encode(&data), c, p }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, key: &RistrettoPoint, data: &[Vec<u8>]) -> bool {
        let M = self.c * key + self.p * G;

        let mut hasher = Sha512::new()
            .chain(key.compress().as_bytes())
            .chain(M.compress().as_bytes());
        
        for d in data {
            hasher.input(d);
        }
        
        let c = Scalar::from_hash(hasher);

        c == self.c
    }
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature with PublicKey (Extended Signature)
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct ExtSignature {
    pub sig: Signature,
    pub key: RistrettoPoint
}

impl Debug for ExtSignature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("ExtSignature")
            .field("sig", &self.sig)
            .field("key", &self.key.encode())
            .finish()
    }
}

impl ExtSignature {
    pub fn id(&self) -> &str {
        &self.sig.encoded
    }

    #[allow(non_snake_case)]
    pub fn sign(s: &Scalar, key: RistrettoPoint, data: &[Vec<u8>]) -> Self {
        let sig = Signature::sign(s, &key, data);
        Self { sig, key }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, data: &[Vec<u8>]) -> bool {
        self.sig.verify(&self.key, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rnd_scalar;

    #[allow(non_snake_case)]
    #[test]
    fn test_correct() {
        let a = rnd_scalar();
        let Pa = a * G;

        let d0 = rnd_scalar();
        let d1 = rnd_scalar();

        let data = &[d0.to_bytes().to_vec(), d1.to_bytes().to_vec()];
        let sig = ExtSignature::sign(&a, Pa, data);
        
        assert!(sig.verify(data) == true);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let a = rnd_scalar();
        let Pa = a * G;

        let d0 = rnd_scalar();
        let d1 = rnd_scalar();
        let d2 = rnd_scalar();
        
        let data1 = &[d0.to_bytes().to_vec(), d1.to_bytes().to_vec()];
        let sig = ExtSignature::sign(&a, Pa, data1);
        
        let data2 = &[d0.to_bytes().to_vec(), d2.to_bytes().to_vec()];
        assert!(sig.verify(data2) == false);
    }
}