use base64::encode;
use ed25519_dalek::{PublicKey, SecretKey};
use rand::rngs::OsRng;

fn main() {
    // Generate a new random secret key
    let secret_key = SecretKey::generate(&mut OsRng);

    // Derive the public key
    let public_key: PublicKey = (&secret_key).into();

    // Encode both to base64
    let private_key_b64 = encode(secret_key.as_bytes());
    let public_key_b64 = encode(public_key.as_bytes());

    println!(
        r#"
Generated Ed25519 Keypair:
==========================
Private key: {private_key_b64}
Public key:  {public_key_b64}

Keep your private key secret!
"#
    );
}
