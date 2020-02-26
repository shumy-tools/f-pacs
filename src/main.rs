mod crypto;
mod structs;

use rand::prelude::*;
use clap::{Arg, ArgMatches, App, SubCommand};
use num_format::{Locale, ToFormattedString};
use std::time::Instant;

use crate::crypto::*;
use crate::crypto::shares::*;
use crate::structs::*;

fn main() {
  let matches = App::new("Statistics for Rn/Fn")
    .version("1.0")
    .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
    .about("Performs time measurements for Rn/Fn (create/recover)")
    
    .subcommand(SubCommand::with_name("Rn")
    .about("Selects the Rn test")
      .arg(Arg::with_name("size")
        .help("Select the Rn chain size")
        .required(true)
        .short("s")
        .takes_value(true))
      .arg(Arg::with_name("threshold")
        .help("Sets the threshold number (t)")
        .required(true)
        .short("t")
        .takes_value(true)))

    .subcommand(SubCommand::with_name("Fn")
    .about("Selects the Fn test")
      .arg(Arg::with_name("size")
        .help("Select the Fn size in MB")
        .required(true)
        .short("s")
        .takes_value(true)))
    .get_matches();

  let skp = KeyPair::new(); // source key-pair
  if matches.is_present("Rn") {
    println!("--Rn test--");
    let sm = matches.subcommand_matches("Rn").unwrap();
    let size = size_cmd(&sm);

    let str_threshold = sm.value_of("threshold").unwrap();
    let t = str_threshold.parse::<usize>().unwrap();
    let n = 2*t + 1;

    println!("Rn-Setup: (t: {}, n: {}, size: {})", t, n, size);
    rn_chain_speed(&skp, t, n, size);

  } else if matches.is_present("Fn") {
    let sm = matches.subcommand_matches("Fn").unwrap();
    let size = size_cmd(&sm);

    println!("Fn-Setup: (size: {}MB)", size);
    fn_adaptor_speed(&skp, size);
  }
}

fn size_cmd(matches: &ArgMatches) -> usize {
  let str_size = matches.value_of("size").unwrap().to_owned();
  str_size.parse::<usize>().unwrap()
}

fn rnd_dn_key() -> [u8; 16] {
  let mut buf = [0u8; 16];
  let mut rng = rand::thread_rng();
  rng.fill_bytes(&mut buf);
  buf
}

fn rn_chain_speed(skp: &KeyPair, t: usize, n: usize, size: usize) {
  // master key-pair distributed in "n" shares
  let ekp = KeyPair::new();
  let poly = Polynomial::rnd(ekp.s, t);
  let ei = poly.shares(n);

  // construct a Rn chain
  let id = "subject-id";
  let set = "dataset-id";
  
  let start = Instant::now();
    let mut lambda: Option<LambdaKey> = None;
    let mut chain: Option<RnChain> = None;
    for i in 0..size {
      match chain.as_mut() {
        None => {
          let rd = RnData { lambda_prev: None, file: RnFileRef { dn: rnd_dn_key(), hfile: format!("file-url-{:?}", i).into_bytes() } };
          let (lamb, r) = Rn::head(&skp, &ekp.key, id, set, rd);
          
          lambda = Some(lamb);
          chain = Some(RnChain::new(r).unwrap());
        },
        Some(chain) => {
          let rd = RnData { lambda_prev: lambda.clone(), file: RnFileRef { dn: rnd_dn_key(), hfile: format!("file-url-{:?}", i).into_bytes() } };
          let (lamb, r) = Rn::tail(&skp, &ekp.key, &chain.lhash, id, set, rd);
          
          lambda = Some(lamb);
          chain.push(r).unwrap();
        }
      }
    }
  let create_time = Instant::now() - start;

  let chain = chain.take().unwrap();

  // recover alpha from a MPC and complete chain
  let start = Instant::now();
    let alpha_i = &ei * chain.kn();
    let alpha = alpha_i.recover().compress();
  let alpha_time = Instant::now() - start;
    let refs = chain.recover(&alpha).unwrap();
  let recover_time = Instant::now() - start;

  let create_speed = (1000 * size as u128)/create_time.as_millis();
  let recover_speed = (1000 * size as u128)/recover_time.as_millis();
  println!("Rn-Test - (create: {}Rn/s, recover: {}Rn/s, alpha: {}ms)",
    create_speed.to_formatted_string(&Locale::en), recover_speed.to_formatted_string(&Locale::en), alpha_time.as_millis().to_formatted_string(&Locale::en));

  // check if the recovered chain is correct
  for (i, r) in refs.iter().enumerate() {
    assert!(std::str::from_utf8(&r.hfile).unwrap() == format!("file-url-{:?}", i));
  }
}

fn fn_adaptor_speed(skp: &KeyPair, size: usize) {
  let dn = rnd_dn_key();

  // generate a random stream of "size" in MB
  let mut plaintext1 = Vec::with_capacity(size * 1024 * 1024);
  let mut rng = rand::thread_rng();
  for _ in 0..size {
    let mut buf = [0u8; 1024 * 1024]; // generate small chunks to avoid explode the stack memory!
    rng.fill_bytes(&mut buf);
    plaintext1.extend_from_slice(&buf);
  }

  let mut plaintext2 = Vec::new();
  let mut ciphertext = Vec::new();

  let start = Instant::now();
    FnAdaptor::save(&skp, &dn, plaintext1.as_slice(), &mut ciphertext).unwrap();
  let encrypt_time = Instant::now() - start;
  
  let start = Instant::now();
    FnAdaptor::load(&dn, ciphertext.as_slice(), &mut plaintext2).unwrap();
  let dencrypt_time = Instant::now() - start;

  let encrypt_speed = (1000 * size as u128)/encrypt_time.as_millis();
  let dencrypt_speed = (1000 * size as u128)/dencrypt_time.as_millis();
  println!("Fn-Test - (encrypt: {}MB/s, dencrypt: {}MB/s)",
    encrypt_speed.to_formatted_string(&Locale::en), dencrypt_speed.to_formatted_string(&Locale::en));
  
  // check if the recovered plaintext is correct
  assert!(plaintext1 == plaintext2);
}
