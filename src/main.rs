mod crypto;
mod structs;

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
}
