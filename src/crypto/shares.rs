use std::fmt::{Debug, Formatter};

use core::ops::{Add, Mul, Sub};
use rand_os::OsRng;
use clear_on_drop::clear::Clear;

use serde::{Serialize, Deserialize};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::crypto::KeyEncoder;

//-----------------------------------------------------------------------------------------------------------
// Scalar Share
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Share {
    pub i: u32,
    pub yi: Scalar
}

impl Drop for Share {
    fn drop(&mut self) {
        self.yi.clear();
    }
}

impl Debug for Share {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Share")
            .field("i", &self.i)
            .field("yi", &self.yi.encode())
            .finish()
    }
}

impl<'a, 'b> Add<&'b Share> for &'a Share {
    type Output = Share;
    fn add(self, rhs: &'b Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi + rhs.yi }
    }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Share {
    type Output = Share;
    fn add(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi + rhs }
    }
}

impl<'a, 'b> Sub<&'b Share> for &'a Share {
    type Output = Share;
    fn sub(self, rhs: &'b Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi - rhs.yi }
    }
}

impl<'a, 'b> Sub<&'b Scalar> for &'a Share {
    type Output = Share;
    fn sub(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi - rhs }
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Share {
    type Output = Share;
    fn mul(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi * rhs }
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Share {
    type Output = RistrettoShare;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoShare {
        RistrettoShare { i: self.i, Yi: self.yi * rhs }
    }
}

//-----------------------------------------------------------------------------------------------------------
// ShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct ShareVector(pub Vec<Share>);

impl ShareVector {
    pub fn recover(&self) -> Scalar {
        let range = self.0.iter().map(|s| Scalar::from(s.i)).collect::<Vec<_>>();

        let mut acc = Scalar::zero();
        for (i, item) in self.0.iter().enumerate() {
            acc += Polynomial::l_i(&range, i) * item.yi;
        }

        acc
    }
}

impl Drop for ShareVector {
    fn drop(&mut self) {
        for item in self.0.iter_mut() {
            item.yi.clear();
        }
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a ShareVector {
    type Output = RistrettoShareVector;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoShareVector {
        let res: Vec<RistrettoShare> = self.0.iter().map(|s| s * rhs).collect();
        RistrettoShareVector(res)
    }
}

//-----------------------------------------------------------------------------------------------------------
// RistrettoShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct RistrettoShareVector(pub Vec<RistrettoShare>);

impl RistrettoShareVector {
    pub fn recover(&self) -> RistrettoPoint {
        let range = self.0.iter().map(|s| Scalar::from(s.i)).collect::<Vec<_>>();

        let mut acc = RistrettoPoint::default();
        for (i, item) in self.0.iter().enumerate() {
            acc += Polynomial::l_i(&range, i) * item.Yi;
        }

        acc
    }
}

//-----------------------------------------------------------------------------------------------------------
// RistrettoShare
//-----------------------------------------------------------------------------------------------------------
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone)]
pub struct RistrettoShare {
    pub i: u32,
    pub Yi: RistrettoPoint
}

impl Debug for RistrettoShare {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("RistrettoShare")
            .field("i", &self.i)
            .field("Yi", &self.Yi.compress().encode())
            .finish()
    }
}

impl<'a, 'b> Add<&'b RistrettoPoint> for &'a RistrettoShare {
    type Output = RistrettoShare;
    fn add(self, rhs: &'b RistrettoPoint) -> RistrettoShare {
        RistrettoShare { i: self.i, Yi: self.Yi + rhs }
    }
}

impl<'a, 'b> Sub<&'b RistrettoPoint> for &'a RistrettoShare {
    type Output = RistrettoShare;
    fn sub(self, rhs: &'b RistrettoPoint) -> RistrettoShare {
        RistrettoShare { i: self.i, Yi: self.Yi - rhs }
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a RistrettoShare {
    type Output = RistrettoShare;
    fn mul(self, rhs: &'b Scalar) -> RistrettoShare {
        RistrettoShare { i: self.i, Yi: self.Yi * rhs }
    }
}


//-----------------------------------------------------------------------------------------------------------
// Shared traits and functions for Polynomial and RistrettoPolynomial
//-----------------------------------------------------------------------------------------------------------
fn cut_tail<Z>(v: &mut Vec::<Z>, elm: Z) where Z: Eq {
    if let Some(i) = v.iter().rev().rposition(|x| *x == elm) {
        v.truncate(i);
    }
}

fn short_mul(a: &mut Vec::<Scalar>, b: Scalar) {
    let mut prev = a[0];
    a[0] *= b;
    for v in a.iter_mut().skip(1) {
        let this = *v;
        *v = prev + *v * b;
        prev = this;
    }
    a.push(Scalar::one());
}

fn lx_num_bar(range: &[Scalar], i: usize) -> (Vec<Scalar>, Scalar) {
    let mut num = vec![Scalar::one()];
    let mut denum = Scalar::one();
    for j in 0..range.len() {
        if j != i {
            short_mul(&mut num, -range[j]);
            denum *= range[i] - range[j];
        }
    }

    (num, denum.invert())
}

pub trait Evaluate {
    type Output;
    fn evaluate(&self, x: &Scalar) -> Self::Output;
}

pub trait Degree {
    fn degree(&self) -> usize;
}

//-----------------------------------------------------------------------------------------------------------
// Polynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    pub a: Vec<Scalar>
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        for item in self.a.iter_mut() {
            item.clear();
        }
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: &'b Scalar) -> Polynomial {
        Polynomial {
            a: self.a.iter().map(|ak| ak * rhs).collect::<Vec<Scalar>>()
        }
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Polynomial {
    type Output = RistrettoPolynomial;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPolynomial {
        RistrettoPolynomial {
            A: self.a.iter().map(|ak| ak * rhs).collect::<Vec<_>>()
        }
    }
}

impl Polynomial {
    pub fn rnd(mut secret: Scalar, degree: usize) -> Self {
        let mut coefs = vec![secret];

        let mut csprng: OsRng = OsRng::new().unwrap();
        let rnd_coefs: Vec<Scalar> = (0..degree).map(|_| Scalar::random(&mut csprng)).collect();
        coefs.extend(rnd_coefs);
        
        // clear secret before drop
        secret.clear();

        Polynomial { a: coefs }
    }

    pub fn l_i(range: &[Scalar], i: usize) -> Scalar {
        let mut num = Scalar::one();
        let mut denum = Scalar::one();
        for j in 0..range.len() {
            if j != i {
                num *= range[j];
                denum *= range[j] - range[i];
            }
        }

        num * denum.invert()
    }

    pub fn shares(&self, n: usize) -> ShareVector {
        let mut shares = Vec::<Share>::with_capacity(n);
        for j in 1..=n {
            let x = Scalar::from(j as u64);
            let share = Share { i: j as u32, yi: self.evaluate(&x) };
            shares.push(share);
        }

        ShareVector(shares)
    }
}

impl Evaluate for Polynomial {
    type Output = Scalar;
    
    fn evaluate(&self, x: &Scalar) -> Scalar {
        // evaluate using Horner's rule
        let mut rev = self.a.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for Polynomial {
    fn degree(&self) -> usize {
        self.a.len() - 1
    }
}

//-----------------------------------------------------------------------------------------------------------
// RistrettoPolynomial
//-----------------------------------------------------------------------------------------------------------
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RistrettoPolynomial {
    pub A: Vec<RistrettoPoint>
}

impl Debug for RistrettoPolynomial {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        let poly: Vec<String> = self.A.iter().map(|p| p.compress().encode()).collect();
        fmt.debug_struct("RistrettoPolynomial")
            .field("A", &poly)
            .finish()
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a RistrettoPolynomial {
    type Output = RistrettoPolynomial;

    #[allow(non_snake_case)]
    fn mul(self, rhs: &'b Scalar) -> RistrettoPolynomial {
        RistrettoPolynomial {
            A: self.A.iter().map(|Ak| Ak * rhs).collect::<Vec<_>>()
        }
    }
}

impl RistrettoPolynomial {
    pub fn verify(&self, share: &RistrettoShare) -> bool {
        let x = Scalar::from(u64::from(share.i));
        share.Yi == self.evaluate(&x)
    }
}

impl Evaluate for RistrettoPolynomial {
    type Output = RistrettoPoint;
    
    fn evaluate(&self, x: &Scalar) -> RistrettoPoint {
        // evaluate using Horner's rule
        let mut rev = self.A.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for RistrettoPolynomial {
    fn degree(&self) -> usize {
        self.A.len() - 1
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{G, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_reconstruct() {
        let threshold = 16;
        let parties = 3*threshold + 1;

        let s = rnd_scalar();
        let S = s * &G;

        let poly = Polynomial::rnd(s, threshold);

        let shares = poly.shares(parties);
        let S_shares = &shares * &G;
        
        let r_s = shares.recover();
        assert!(s == r_s);

        let r_S = S_shares.recover();
        assert!(S == r_S);
    }
}