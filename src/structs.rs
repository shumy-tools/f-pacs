#![forbid(unsafe_code)]
#![allow(dead_code)]

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use std::io::{Read, Write};

use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
use aesstream::{AesWriter, AesReader};

use crate::crypto::*;
use crate::crypto::signatures::*;

pub type BoxError = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, BoxError>;

#[inline]
pub fn error(msg: &str) -> BoxError { From::from(msg) }

//-----------------------------------------------------------------------------------------------------------
// LambdaKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct LambdaKey {
    key: Vec<u8>
}

impl LambdaKey {
    pub fn new(alpha: &CompressedRistretto, id: &str, set: &str) -> Self {
        let key = Sha256::new()
            .chain(alpha.as_bytes())
            .chain(id)
            .chain(set)
            .result().to_vec();
        
        Self { key }
    }

    pub fn k128(&self) -> &[u8; 16] {
        arrayref::array_ref!(self.key, 0, 16)
    }

    pub fn k192(&self) -> &[u8; 24] {
        arrayref::array_ref!(self.key, 0, 24)
    }

    pub fn k256(&self) -> &[u8; 32] {
        arrayref::array_ref!(self.key, 0, 32)
    }
}

//-----------------------------------------------------------------------------------------------------------
// RnChain
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RnFileRef {
    pub dn: [u8; 16],
    pub hfile: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RnChain {
    pub lhash: Vec<u8>, // last Rn hash
    pub chain: Vec<Rn>
}

impl RnChain {
    pub fn id(&self) -> &str {
        self.chain.first().unwrap().id.as_ref().unwrap()
    }

    pub fn set(&self) -> &str {
        self.chain.first().unwrap().set.as_ref().unwrap()
    }

    pub fn kn(&self) -> &RistrettoPoint {
        &self.chain.last().unwrap().data.kn
    }

    pub fn new(head: Rn) -> Result<Self> {
        let lhash = head.check()?;
        if head.id.is_none() {
            Err("Record is not a head type!")?
        }
        
        Ok(Self { lhash, chain: vec![head] })
    }

    pub fn push(&mut self, tail: Rn) -> Result<()> {
        let dhash = tail.check()?;

        let hprev = tail.hprev.as_ref().ok_or_else(|| error("Record is not a tail type!"))?;
        if &self.lhash != hprev {
            Err("Incorrect hash chain!")?
        }

        self.lhash = dhash;
        self.chain.push(tail);

        Ok(())
    }

    pub fn recover(&self, alpha: &CompressedRistretto) -> Result<Vec<RnFileRef>> {
        let id = self.id();
        let set = self.set();

        let mut lambda = Some(LambdaKey::new(alpha, id, set));
        let mut chain = Vec::<RnFileRef>::new();
        for rn in self.chain.iter().rev() {
            let data = rn.data.data(&lambda.as_ref().unwrap())?;
            lambda = data.lambda_prev;
            chain.push(data.file);
        }

        chain.reverse();
        Ok(chain)
    }
}

//-----------------------------------------------------------------------------------------------------------
// Rn data structure
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RnData {
    pub lambda_prev: Option<LambdaKey>,
    pub file: RnFileRef
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RnEncData {
    pub kn: RistrettoPoint,
    data: Vec<u8>
}

impl RnEncData {
    fn new(ekey: &RistrettoPoint, id: &str, set: &str, cd: &RnData) -> (LambdaKey, Self) {
        let k = rnd_scalar();
        let alpha = (k * ekey).compress();
        let lambda = LambdaKey::new(&alpha, id, set);

        // E_{lambda} [kn_prev, dn, hfile]
        let mut data = Vec::new();
        {
            let encryptor = AesSafe128Encryptor::new(lambda.k128());
            let mut writer = AesWriter::new(&mut data, encryptor).unwrap();
            let b_cd = bincode::serialize(cd).unwrap();
            writer.write_all(&b_cd).unwrap();
        }

        (lambda, Self { kn: (k * &G), data })
    }

    fn data(&self, lambda: &LambdaKey) -> Result<RnData> {
        // D_{lambda} [kn_prev, dn, hfile]
        let mut data = Vec::new();
        {
            let decryptor = AesSafe128Decryptor::new(lambda.k128());
            let mut reader = AesReader::new(self.data.as_slice(), decryptor)?;
            reader.read_to_end(&mut data)?;
        }

        let cd: RnData = bincode::deserialize(&data)?;
        Ok(cd)
    }

    fn to_vec(&self) -> Vec<u8> {
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

    pub fn head(keyp: &KeyPair, ekey: &RistrettoPoint, id: &str, set: &str, rd: RnData) -> (LambdaKey, Self) {
        let (lambda, data) = RnEncData::new(ekey, id, set, &rd);
        let dhash = Sha256::new()
            .chain(id)
            .chain(set)
            .chain(data.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());
        (lambda, Self { id: Some(id.into()), set: Some(set.into()), hprev: None, data, sig })
    }

    pub fn tail(keyp: &KeyPair, ekey: &RistrettoPoint, hprev: &[u8], id: &str, set: &str, rd: RnData) -> (LambdaKey, Self) {
        let (lambda, data) = RnEncData::new(ekey, id, set, &rd);
        let dhash = Sha256::new()
            .chain(hprev)
            .chain(data.to_vec())
            .result();

        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());
        (lambda, Self { id: None, set: None, hprev: Some(hprev.into()), data, sig })
    }

    pub fn check(&self) -> Result<Vec<u8>> {
        let dhash = self.hash();
        if !self.sig.verify(&dhash) {
            Err("Invalid record signature!")?
        }

        Ok(dhash)
    }

    pub fn hash(&self) -> Vec<u8> {
        let dhash = match self.id {
            Some(_) => Sha256::new()
                .chain(self.id.as_ref().unwrap())
                .chain(self.set.as_ref().unwrap())
                .chain(self.data.to_vec())
                .result(),
            None => Sha256::new()
                .chain(self.hprev.as_ref().unwrap())
                .chain(self.data.to_vec())
                .result()
        };

        dhash.to_vec()
    }
}

//-----------------------------------------------------------------------------------------------------------
// FnAdaptor (read/write)
//-----------------------------------------------------------------------------------------------------------
/*fn copy_until<R: Read, W: Write>(mut from: R, mut to: W, reminder: &mut [u8]) -> std::io::Result<u64> {
    const BUF_SIZE: usize = 1024*1024;
    let size = reminder.len();

    // double buffer reader
    let mut total = 064;
    let mut back_as_data = true;
    let mut buf1 = [0u8; BUF_SIZE];
    let mut buf2 = [0u8; BUF_SIZE];
    let mut front = buf1.as_ref();
    let mut back = buf2.as_ref();
    loop {
        if back_as_data {
            total += 
            to.write(back)?;
        }

        let size = from.read(&mut front)?;
        if size == 1024*1024 { // continue
            std::mem::swap(&mut front, &mut back);
            back_as_data = true;
        } else { // last data block
            to.write_all(&front[..size]);
            break;
        }
    }

    // grab signature data!
    let b_sig = [0u8; SIG_SIZE];
    back.chain(front).iter().rev().take(SIG_SIZE);
    Ok(total)
}*/

pub struct WriteInterceptor<W: Write, F: FnMut(&[u8]) -> ()>(W, F);
impl<W: Write, F: FnMut(&[u8]) -> ()> Write for WriteInterceptor<W, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.1)(buf);
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

pub struct ReadInterceptor<R: Read, F: FnMut(&[u8]) -> ()>(R, F);
impl<R: Read, F: FnMut(&[u8]) -> ()> Read for ReadInterceptor<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.0.read(buf)?;
        (self.1)(&buf[..size]);
        Ok(size)
    }
}

pub struct ReadUntil<R: Read>{
    from: R,
    buffer: Vec<u8>,
    remainder: usize,
    end: usize
}

impl<R: Read> Read for ReadUntil<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total = 0usize;
        while total != buf.len() {
            self.end += self.from.read(&mut self.buffer[self.end..])?;
            if self.end < self.remainder {
                use std::io::{Error, ErrorKind};
                return Err(Error::new(ErrorKind::InvalidInput, format!("Expected input size of at least {}", self.remainder)));
            }

            let top = self.end - self.remainder;
            if top == 0 { break; }
            
            let left = buf.len() - total;
            let moved = if top <= left { top } else { left };

            let slice = &mut buf[total..(total + moved)];
            slice.copy_from_slice(&self.buffer[..moved]);

            // FIX: rotate_left is not efficient - should only copy [moved..self.end]
            self.buffer.rotate_left(moved);
            //self.buffer.drain(..moved);
            //self.buffer.extend_from_slice(&[0u8; moved]);
            
            self.end -= moved;
            total += moved;
        }
        
        Ok(total)
    }
}

impl<R: Read> ReadUntil<R> {
    pub fn new(from: R, remainder: usize) -> Self {
        Self { from, buffer: vec![0u8; 1024 + remainder], remainder, end: 0 }
    }

    pub fn remainder(&self) -> &[u8] {
        &self.buffer[..self.end]
    }
}

pub struct FnAdaptor;
impl FnAdaptor {
    pub fn save<R: Read, W: Write>(keyp: &KeyPair, dn: &[u8; 16], mut from: R, mut to: W) -> Result<()> {
        let mut hasher = Sha256::new();
        let encryptor = AesSafe128Encryptor::new(dn);

        // write and hash ciphertext
        {// from(plaintext) -> writer -> interceptor -> to(ciphertext)
            let mut interceptor = WriteInterceptor(&mut to, |buf| hasher.input(buf));
            let mut writer = AesWriter::new(&mut interceptor, encryptor)?;
            std::io::copy(&mut from, &mut writer)?;
        };

        // construct signature
        let dhash = hasher.result();
        let sig = ExtSignature::sign(&keyp.s, keyp.key.clone(), dhash.as_slice());
        
        // write signature
        let b_sig = bincode::serialize(&sig)?; // NOTE: bincode::serialize(&sig) results in 136 bytes!
        to.write_all(&b_sig)?;

        Ok(())
    }

    pub fn load<R: Read, W: Write>(dn: &[u8; 16], mut from: R, mut to: W) -> Result<()> {
        let mut hasher = Sha256::new();
        let decryptor = AesSafe128Decryptor::new(dn);
        let mut encrypted = ReadUntil::new(&mut from, 136); // NOTE: bincode::serialize(&sig) results in 136 bytes!

        // read and hash ciphertext
        {// from(ciphertext) -> interceptor -> reader -> to(plaintext)
            let mut interceptor = ReadInterceptor(&mut encrypted, |buf| hasher.input(buf));
            let mut reader = AesReader::new(&mut interceptor, decryptor)?;
            std::io::copy(&mut reader, &mut to)?;
        };

        // read signature
        let b_sig = encrypted.remainder();
        let sig: ExtSignature = bincode::deserialize(b_sig)?;

        // verify signature
        let dhash = hasher.result();
        if !sig.verify(&dhash) {
            Err("Signature verification failed!")?
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

        let cd1 = RnData { lambda_prev: None, file: RnFileRef { dn: *b"encryption123456", hfile: b"file-url".to_vec() } };
        let (_, r1) = Rn::head(&skp, &ekp.key, id, set, cd1.clone());
        assert!(r1.check().is_ok());

        let alpha = (ekp.s * &r1.data.kn).compress();
        let lambda = LambdaKey::new(&alpha, id, set);
        let cd2 = r1.data.data(&lambda).unwrap();
        assert!(cd1 == cd2);
    }

    #[test]
    fn chain_write_load() {
        let ekp = KeyPair::new(); // master key-pair
        let skp = KeyPair::new(); // source key-pair

        let id = "subject-id";
        let set = "dataset-id";

            let rd = RnData { lambda_prev: None, file: RnFileRef { dn: *b"encryption123456", hfile: b"file-1-url".to_vec() } };
            let (lamb, r) = Rn::head(&skp, &ekp.key, id, set, rd);
        
        let mut chain = RnChain::new(r).unwrap();

            let rd = RnData { lambda_prev: Some(lamb), file: RnFileRef { dn: *b"encryption654321", hfile: b"file-2-url".to_vec() } };
            let (lamb, r) = Rn::tail(&skp, &ekp.key, &chain.lhash, id, set, rd);

        chain.push(r).unwrap();

            let rd = RnData { lambda_prev: Some(lamb), file: RnFileRef { dn: *b"encryption564321", hfile: b"file-3-url".to_vec() } };
            let (_, r) = Rn::tail(&skp, &ekp.key, &chain.lhash, id, set, rd);

        chain.push(r).unwrap();

        // recover the original set of RnFileRef
        let alpha = (ekp.s * chain.kn()).compress();
        let refs = chain.recover(&alpha).unwrap();

        let mut res: String = "".into();
        for r in refs.iter() {
          res += &format!("(dn={}, hfile={})", std::str::from_utf8(&r.dn).unwrap(), std::str::from_utf8(&r.hfile).unwrap());
        }

        assert!(res == "(dn=encryption123456, hfile=file-1-url)(dn=encryption654321, hfile=file-2-url)(dn=encryption564321, hfile=file-3-url)");
    }

    #[test]
    fn file_write_load() {
        let dn = b"encryption123456";
        let data = b"sjdhflasdvbasliyfbrlaiybasrivbaskdvjb4o837t239846g5uybgsidufbyv586fge58b6ves58dsfgsdfgsdfg";
        let skp = KeyPair::new(); // source key-pair
        
        let mut plaintext1 = Vec::new();
        plaintext1.extend(data.to_vec());
        let mut ciphertext = Vec::new();

        // write data
        FnAdaptor::save(&skp, dn, plaintext1.as_slice(), &mut ciphertext).unwrap();

        // read data
        let mut plaintext2 = Vec::new();
        FnAdaptor::load(dn, ciphertext.as_slice(), &mut plaintext2).unwrap();

        assert!(plaintext1 == plaintext2);
    }
}