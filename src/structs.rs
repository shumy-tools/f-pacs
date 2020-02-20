#![forbid(unsafe_code)]
#![allow(dead_code)]

use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use std::io::{Read, Write, Cursor};
use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
use aesstream::{AesWriter, AesReader};

use crate::crypto::*;
use crate::crypto::signatures::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

//-----------------------------------------------------------------------------------------------------------
// Chain structure
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ChainData {
    pub lambda_prev: Option<Vec<u8>>,
    pub dn: Vec<u8>,
    pub hfile: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Chain {
    pub kn: RistrettoPoint,
    data: Vec<u8>
}

impl Chain {
    pub fn lambda(alpha: &CompressedRistretto, id: &str, set: &str) -> Vec<u8> {
        Sha512::new()
            .chain(alpha.as_bytes())
            .chain(id)
            .chain(set)
            .result().to_vec()
    }

    pub fn new(ekey: &RistrettoPoint, id: &str, set: &str, cd: &ChainData) -> Result<Self> {
        let k = rnd_scalar();
        let alpha = (k * ekey).compress();
        let lambda = Chain::lambda(&alpha, id, set);

        // E_{lambda} [kn_prev, dn, hfile]
        let mut data = Vec::new();
        {
            let encryptor = AesSafe128Encryptor::new(&lambda[..16]);
            let mut writer = AesWriter::new(&mut data, encryptor)?;
            let b_cd = bincode::serialize(cd)?;
            writer.write_all(&b_cd)?;
        }

        Ok(Self { kn: (k * &G), data })
    }

    pub fn data(&self, alpha: &CompressedRistretto, id: &str, set: &str) -> Result<ChainData> {
        let lambda = Chain::lambda(alpha, id, set);

        // D_{lambda} [kn_prev, dn, hfile]
        let mut data = Vec::new();
        {
            let decryptor = AesSafe128Decryptor::new(&lambda[..16]);
            let mut reader = AesReader::new(Cursor::new(&self.data), decryptor)?;
            reader.read_to_end(&mut data)?;
        }

        let cd: ChainData = bincode::deserialize(&data)?;
        Ok(cd)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let kn_comp = self.kn.compress();
        let data: &[&[u8]] = &[kn_comp.as_bytes(), &self.data];
        data.concat()
    }
}

//-----------------------------------------------------------------------------------------------------------
// Rn structure
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Rn {
    pub id: Option<String>,
    pub set: Option<String>,
    pub hprev: Option<Vec<u8>>,
    pub chain: Chain,
    sig: ExtSignature
}

impl Rn {
    pub fn owner(&self) -> &RistrettoPoint {
        &self.sig.key
    }

    pub fn head(keyp: &KeyPair, id: &str, set: &str, chain: Chain) -> Self {
        let dhash = Sha512::new()
            .chain(id)
            .chain(set)
            .chain(chain.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Self { id: Some(id.into()), set: Some(set.into()), hprev: None, chain, sig }
    }

    pub fn tail(keyp: &KeyPair, hprev: &[u8], chain: Chain) -> Self {
        let dhash = Sha512::new()
            .chain(hprev)
            .chain(chain.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Self { id: None, set: None, hprev: Some(hprev.into()), chain, sig }
    }

    pub fn hash(&self) -> Vec<u8> {
        let dhash = match self.id {
            Some(_) => Sha512::new()
                .chain(self.id.as_ref().unwrap())
                .chain(self.set.as_ref().unwrap())
                .chain(self.chain.to_vec())
                .result(),
            None => Sha512::new()
                .chain(self.hprev.as_ref().unwrap())
                .chain(self.chain.to_vec())
                .result()
        };

        dhash.to_vec()
    }

    pub fn check(&self) -> bool {
        let dhash = self.hash();
        self.sig.verify(&dhash)
    }
}

//-----------------------------------------------------------------------------------------------------------
// FnAdaptor (read/write)
//-----------------------------------------------------------------------------------------------------------
pub struct FnAdaptor;

impl FnAdaptor {
    pub fn save<R: Read, W: Write>(keyp: &KeyPair, dn: &[u8; 16], mut from: R, mut to: W) -> Result<ExtSignature> {
        let encryptor = AesSafe128Encryptor::new(dn);
        let mut writer = AesWriter::new(&mut to, encryptor)?;

        let mut hasher = Sha512::new();
        let mut buf = [0u8; 1024*1024];
        loop {
            let size = from.read(&mut buf)?;
            if size == 0 {
                break;
            }

            // FIX: hash of the plaintext! Not the best security.
            hasher.input(&buf[..size]);
            writer.write(&buf[..size])?;
        }
        writer.flush()?;

        let dhash = hasher.result();
        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Ok(sig)
    }

    pub fn load<R: Read, W: Write>(sig: &ExtSignature, dn: &[u8; 16], mut from: R, mut to: W) -> Result<()> {
        let decryptor = AesSafe128Decryptor::new(dn);
        let mut reader = AesReader::new(&mut from, decryptor)?;

        let mut hasher = Sha512::new();
        let mut buf = [0u8; 1024*1024];
        loop {
            let size = reader.read(&mut buf)?;
            if size == 0 {
                break;
            }

            // FIX: hash of the plaintext! Not the best security.
            hasher.input(&buf[..size]);
            to.write(&buf[..size])?;
        }
        to.flush()?;

        let dhash = hasher.result();
        if !sig.verify(&dhash) {
            return Err("Signature verification failed!".into());
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_write_load() {
        let ekp = KeyPair::new(); // master key-pair
        let skp = KeyPair::new(); // source key-pair

        let id = "subject-id";
        let set = "dataset-id";

        let dn = b"encryption123456".to_vec();
        let hfile = b"file-url".to_vec();

        let cd1 = ChainData { lambda_prev: None, dn, hfile };
        let c1 = Chain::new(&ekp.key, id, set, &cd1).unwrap();
        let r1 = Rn::head(&skp, id, set, c1);
        assert!(r1.check());

        let alpha = (ekp.s * &r1.chain.kn).compress();
        let cd2 = r1.chain.data(&alpha, id, set).unwrap();
        assert!(cd1 == cd2);
    }

    #[test]
    fn file_write_load() {
        let dn = b"encryption123456";
        let data = b"sjdhflasdvbasliyfbrlaiybasrivbaskdvjb4o837t239846g5uybgsidufbyv586fge58b6ves58";
        let kp = KeyPair::new();
        
        let mut plaintext1 = Vec::new();
        plaintext1.extend(data.to_vec());
        let mut ciphertext = Vec::new();

        // write data
        let sig = FnAdaptor::save(&kp, dn, Cursor::new(&plaintext1), &mut ciphertext).unwrap();

        // read data
        let mut plaintext2 = Vec::new();
        FnAdaptor::load(&sig, dn, Cursor::new(&ciphertext), &mut plaintext2).unwrap();

        assert!(plaintext1 == plaintext2);
    }
}