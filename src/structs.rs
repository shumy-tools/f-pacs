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
pub struct RnData {
    pub lambda_prev: Option<Vec<u8>>,
    pub dn: Vec<u8>,
    pub hfile: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RnEncData {
    pub kn: RistrettoPoint,
    data: Vec<u8>
}

impl RnEncData {
    pub fn lambda(alpha: &CompressedRistretto, id: &str, set: &str) -> Vec<u8> {
        Sha512::new()
            .chain(alpha.as_bytes())
            .chain(id)
            .chain(set)
            .result().to_vec()
    }

    pub fn new(ekey: &RistrettoPoint, id: &str, set: &str, cd: &RnData) -> Result<Self> {
        let k = rnd_scalar();
        let alpha = (k * ekey).compress();
        let lambda = RnEncData::lambda(&alpha, id, set);

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

    pub fn data(&self, alpha: &CompressedRistretto, id: &str, set: &str) -> Result<RnData> {
        let lambda = RnEncData::lambda(alpha, id, set);

        // D_{lambda} [kn_prev, dn, hfile]
        let mut data = Vec::new();
        {
            let decryptor = AesSafe128Decryptor::new(&lambda[..16]);
            let mut reader = AesReader::new(Cursor::new(&self.data), decryptor)?;
            reader.read_to_end(&mut data)?;
        }

        let cd: RnData = bincode::deserialize(&data)?;
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
    pub data: RnEncData,
    sig: ExtSignature
}

impl Rn {
    pub fn owner(&self) -> &RistrettoPoint {
        &self.sig.key
    }

    pub fn head(keyp: &KeyPair, id: &str, set: &str, data: RnEncData) -> Self {
        let dhash = Sha512::new()
            .chain(id)
            .chain(set)
            .chain(data.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Self { id: Some(id.into()), set: Some(set.into()), hprev: None, data, sig }
    }

    pub fn tail(keyp: &KeyPair, hprev: &[u8], data: RnEncData) -> Self {
        let dhash = Sha512::new()
            .chain(hprev)
            .chain(data.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Self { id: None, set: None, hprev: Some(hprev.into()), data, sig }
    }

    pub fn hash(&self) -> Vec<u8> {
        let dhash = match self.id {
            Some(_) => Sha512::new()
                .chain(self.id.as_ref().unwrap())
                .chain(self.set.as_ref().unwrap())
                .chain(self.data.to_vec())
                .result(),
            None => Sha512::new()
                .chain(self.hprev.as_ref().unwrap())
                .chain(self.data.to_vec())
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
pub struct WriteInterceptor<W: Write, F: FnMut(&[u8]) -> ()>(pub W, pub F);
impl<W: Write, F: FnMut(&[u8]) -> ()> Write for WriteInterceptor<W, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.1)(buf);
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

pub struct ReadInterceptor<R: Read, F: FnMut(&[u8]) -> ()>(pub R, pub F);
impl<R: Read, F: FnMut(&[u8]) -> ()> Read for ReadInterceptor<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.0.read(buf)?;
        (self.1)(&buf[..size]);
        Ok(size)
    }
}

pub struct FnAdaptor;
impl FnAdaptor {
    pub fn save<R: Read, W: Write>(keyp: &KeyPair, dn: &[u8; 16], mut from: R, mut to: W) -> Result<ExtSignature> {
        let mut hasher = Sha512::new();
        {
            let encryptor = AesSafe128Encryptor::new(dn);

            // from(plaintext) -> writer -> interceptor -> to(ciphertext)
            let mut interceptor = WriteInterceptor(&mut to, |buf| hasher.input(buf));
            let mut writer = AesWriter::new(&mut interceptor, encryptor)?;
            std::io::copy(&mut from, &mut writer)?;
        }

        let dhash = hasher.result();
        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());

        Ok(sig)
    }

    pub fn load<R: Read, W: Write>(sig: &ExtSignature, dn: &[u8; 16], mut from: R, mut to: W) -> Result<()> {
        let mut hasher = Sha512::new();
        {
            let decryptor = AesSafe128Decryptor::new(dn);
            
            // from(ciphertext) -> interceptor -> reader -> to(plaintext)
            let mut interceptor = ReadInterceptor(&mut from, |buf| hasher.input(buf));
            let mut reader = AesReader::new(&mut interceptor, decryptor)?;
            std::io::copy(&mut reader, &mut to)?;
        }

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

        let cd1 = RnData { lambda_prev: None, dn, hfile };
        let c1 = RnEncData::new(&ekp.key, id, set, &cd1).unwrap();
        let r1 = Rn::head(&skp, id, set, c1);
        assert!(r1.check());

        let alpha = (ekp.s * &r1.data.kn).compress();
        let cd2 = r1.data.data(&alpha, id, set).unwrap();
        assert!(cd1 == cd2);
    }

    #[test]
    fn file_write_load() {
        let dn = b"encryption123456";
        let data = b"sjdhflasdvbasliyfbrlaiybasrivbaskdvjb4o837t239846g5uybgsidufbyv586fge58b6ves58";
        let skp = KeyPair::new(); // source key-pair
        
        let mut plaintext1 = Vec::new();
        plaintext1.extend(data.to_vec());
        let mut ciphertext = Vec::new();

        // write data
        let sig = FnAdaptor::save(&skp, dn, Cursor::new(&plaintext1), &mut ciphertext).unwrap();

        // read data
        let mut plaintext2 = Vec::new();
        FnAdaptor::load(&sig, dn, Cursor::new(&ciphertext), &mut plaintext2).unwrap();

        assert!(plaintext1 == plaintext2);
    }
}