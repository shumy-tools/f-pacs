mod crypto;
mod structs;

use std::time::{Instant, Duration};

use crate::crypto::*;
use crate::crypto::shares::*;
use crate::structs::*;

fn main() {
  let threshold = 16;
  let parties = 3*threshold + 1;

  let ekp = KeyPair::new(); // master key-pair
  let poly = Polynomial::rnd(ekp.s, threshold);
  let ei = poly.shares(parties);

  
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

  // recover alpha from a MPC
  let alpha_i = &ei * chain.kn();
  let alpha = alpha_i.recover().compress();

  let refs = chain.recover(&alpha).unwrap();
  for r in refs.iter() {
    println!("({}, {})", std::str::from_utf8(&r.dn).unwrap(), std::str::from_utf8(&r.hfile).unwrap());
  }

  // testing FnAdaptor speed
  use rand::prelude::*;

  let dn = b"encryption123456";
  let skp = KeyPair::new();

  const SIZE: usize = 500; // generate a random stream of SIZE in MB
  let mut plaintext1 = Vec::with_capacity(SIZE * 1024 * 1024);
  let mut rng = rand::thread_rng();
  for _ in 0..SIZE {
    let mut buf = [0u8; 1024 * 1024]; // generate small chunks to avoid explode the stack memory!
    rng.fill_bytes(&mut buf);
    plaintext1.extend_from_slice(&buf);
  }
  println!("GENERATED: {:?}MB", plaintext1.len()/(1024 * 1024));

  let mut plaintext2 = Vec::new();
  let mut ciphertext = Vec::new();

  let start = Instant::now();
  FnAdaptor::save(&skp, dn, plaintext1.as_slice(), &mut ciphertext).unwrap();
  let save_time = Instant::now() - start;
  println!("SAVE: {:?}MB/s", (1000 * SIZE as u128)/save_time.as_millis());
  
  let start = Instant::now();
  FnAdaptor::load(dn, ciphertext.as_slice(), &mut plaintext2).unwrap();
  let load_time = Instant::now() - start;
  println!("LOAD: {:?}MB/s", (1000 * SIZE as u128)/load_time.as_millis());

  assert!(plaintext1 == plaintext2);
}
