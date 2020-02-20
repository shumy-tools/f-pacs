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
    pub c: Scalar,
    pub p: Scalar
}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(&self.encode())
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let ss = SerializedSignature { sig: self.encode() };
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

        let c = Scalar::from_canonical_bytes(c_bytes)
            .ok_or_else(|| Error::custom("Invalid c scalar!"))?;
        
        let p = Scalar::from_canonical_bytes(p_bytes)
            .ok_or_else(|| Error::custom("Invalid p scalar!"))?;

        Ok(Signature { c, p })
    }
}

impl Signature {
    fn encode(&self) -> String {
        let data: &[&[u8]] = &[self.c.as_bytes(), self.p.as_bytes()];
        let data = data.concat();
        base64::encode(&data)
    }

    #[allow(non_snake_case)]
    pub fn sign(s: &Scalar, key: &RistrettoPoint, dhash: &[u8]) -> Self {
        let hasher = Sha512::new()
            .chain(s.as_bytes())
            .chain(dhash);

        let m = Scalar::from_hash(hasher); 
        let M = (m * G).compress();

        let hasher = Sha512::new()
            .chain(key.compress().as_bytes())
            .chain(M.as_bytes())
            .chain(dhash);

        let c = Scalar::from_hash(hasher);
        let p = m - c * s;

        Self { c, p }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, key: &RistrettoPoint, dhash: &[u8]) -> bool {
        let M = self.c * key + self.p * G;

        let hasher = Sha512::new()
            .chain(key.compress().as_bytes())
            .chain(M.compress().as_bytes())
            .chain(dhash);
        
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
    #[allow(non_snake_case)]
    pub fn sign(s: &Scalar, key: RistrettoPoint, dhash: &[u8]) -> Self {
        let sig = Signature::sign(s, &key, dhash);
        Self { sig, key }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, dhash: &[u8]) -> bool {
        self.sig.verify(&self.key, dhash)
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

        let dhash = Sha512::new()
            .chain(d0.as_bytes())
            .chain(d1.as_bytes())
            .result();

        let sig = ExtSignature::sign(&a, Pa, dhash.as_slice());
        assert!(sig.verify(dhash.as_slice()) == true);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let a = rnd_scalar();
        let Pa = a * G;

        let d0 = rnd_scalar();
        let d1 = rnd_scalar();
        let d2 = rnd_scalar();
        
        let dhash1 = Sha512::new()
            .chain(d0.as_bytes())
            .chain(d1.as_bytes())
            .result();

        let sig = ExtSignature::sign(&a, Pa, dhash1.as_slice());
        
        let dhash2 = Sha512::new()
            .chain(d0.as_bytes())
            .chain(d2.as_bytes())
            .result();
        
        assert!(sig.verify(dhash2.as_slice()) == false);
    }
}