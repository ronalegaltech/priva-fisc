// rsa_key_hash - the key hash that the circuits publish, computed from an RSA-2048 modulus.
//
// Anyone can execute this (no proof needed) on the modulus taken from a certificate and compare
// the output with the issuer or taxpayer key hash published by a proof. See tools/efi/keyhash.py.

use pf_xmldsig::rsa_key_hash;

fn main(modulus: [u128; 18]) -> pub Field {
    rsa_key_hash(modulus)
}
