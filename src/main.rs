mod crypto;
mod structs;

use std::io::Cursor;
use crate::crypto::*;
use crate::structs::*;

fn main() {
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
