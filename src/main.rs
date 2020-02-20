mod crypto;
mod structs;

use crate::crypto::*;
use crate::crypto::shares::*;

fn main() {
  let threshold = 16;
  let parties = 3*threshold + 1;

  let s = rnd_scalar();
  let S = s * &G;

  let poly = Polynomial::rnd(s, threshold);
  let S_poly = &poly * &G;

  let shares = poly.shares(parties);
  let S_shares = shares.0.iter().map(|s| s * &G).collect::<Vec<_>>();

  let r_s = Polynomial::interpolate(&shares.0[..2*threshold + 1]);
  println!("SECRET: {:?}", s == r_s);

  let r_poly = Polynomial::reconstruct(&shares.0[..2*threshold + 1]);
  println!("{:?} - {:?}", poly.a.len(), r_poly.a.len());


  let r_S = RistrettoPolynomial::interpolate(&S_shares[..2*threshold + 1]);
  println!("SECRET-P: {:?}", S == r_S);

  let S_r_poly = RistrettoPolynomial::reconstruct(&S_shares[..2*threshold + 1]);
  println!("{:?} - {:?}", S_poly.A.len(), S_r_poly.A.len());
}
