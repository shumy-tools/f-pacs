mod crypto;
mod structs;

use crate::crypto::*;
use crate::structs::*;

fn main() {
  let ekp = KeyPair::new(); // master key-pair
  let skp = KeyPair::new(); // source key-pair

  let id = "subject-id";
  let set = "dataset-id";

    let rd = RnData { lambda_prev: None, file: RnFileRef { dn: *b"encryption123456", hfile: b"file-1-url".to_vec() } };
    let r = Rn::head(&skp, &ekp.key, id, set, rd);
    let alpha = (ekp.s * &r.data.kn).compress();

  let mut chain = RnChain::new(r).unwrap();

    let lamb = lambda(&alpha, id, set);
    let rd = RnData { lambda_prev: Some(lamb), file: RnFileRef { dn: *b"encryption654321", hfile: b"file-2-url".to_vec() } };
    let r = Rn::tail(&skp, &ekp.key, &chain.lhash, id, set, rd);
    let alpha = (ekp.s * &r.data.kn).compress();

  chain.push(r).unwrap();

    let lamb = lambda(&alpha, id, set);
    let rd = RnData { lambda_prev: Some(lamb), file: RnFileRef { dn: *b"encryption564321", hfile: b"file-3-url".to_vec() } };
    let r = Rn::tail(&skp, &ekp.key, &chain.lhash, id, set, rd);
    let alpha = (ekp.s * &r.data.kn).compress();

  chain.push(r).unwrap();

  let refs = chain.recover(&alpha).unwrap();
  let mut res: String = "".into();
  for r in refs.iter() {
    res += &format!("(dn={}, hfile={})", std::str::from_utf8(&r.dn).unwrap(), std::str::from_utf8(&r.hfile).unwrap());
  }

  println!("{}", res);
}
