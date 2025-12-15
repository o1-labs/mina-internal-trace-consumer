use base64::encode;
use ed25519_dalek::{PublicKey, SecretKey};
use rand::rngs::OsRng;

fn main() {
    // Generate a new random secret key
    let mut csprng = OsRng {};
    let secret_key = SecretKey::generate(&mut csprng);

    // Derive the public key
    let public_key: PublicKey = (&secret_key).into();

    // Encode both to base64
    let private_key_b64 = encode(secret_key.as_bytes());
    let public_key_b64 = encode(public_key.as_bytes());

    println!("Generated Ed25519 Keypair:");
    println!("==========================");
    println!("Private key: {}", private_key_b64);
    println!("Public key:  {}", public_key_b64);
    println!();
    println!("Keep your private key secret!");
}
