use crate::error::{Error, Result};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ctr::Ctr128BE;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

pub type Aes128Ctr = Ctr128BE<Aes128>;
pub type Aes192Ctr = Ctr128BE<Aes192>;
pub type Aes256Ctr = Ctr128BE<Aes256>;

pub fn decrypt_message(
    private_key: &RsaPrivateKey,
    encrypted_key: &str,
    encrypted_message: &str,
    url: &str,
) -> Result<Vec<u8>> {
    let decoded_key = BASE64
        .decode(encrypted_key)
        .map_err(|source| Error::Crypto {
            url: url.to_string(),
            message: format!("failed to decode RSA-encrypted AES key: {source}"),
        })?;
    let aes_key = private_key
        .decrypt(Oaep::new::<Sha256>(), &decoded_key)
        .map_err(|source| Error::Crypto {
            url: url.to_string(),
            message: format!("failed to decrypt AES key with RSA-OAEP: {source}"),
        })?;
    let ciphertext = BASE64
        .decode(encrypted_message)
        .map_err(|source| Error::Crypto {
            url: url.to_string(),
            message: format!("failed to decode encrypted interaction payload: {source}"),
        })?;
    if ciphertext.len() < 16 {
        return Err(Error::Crypto {
            url: url.to_string(),
            message: "ciphertext block size is too small".to_string(),
        });
    }

    let (iv, body) = ciphertext.split_at(16);
    let mut plaintext = body.to_vec();
    match aes_key.len() {
        16 => {
            let mut cipher =
                Aes128Ctr::new_from_slices(&aes_key, iv).map_err(|source| Error::Crypto {
                    url: url.to_string(),
                    message: format!("failed to initialize AES-128-CTR: {source}"),
                })?;
            cipher.apply_keystream(&mut plaintext);
        }
        24 => {
            let mut cipher =
                Aes192Ctr::new_from_slices(&aes_key, iv).map_err(|source| Error::Crypto {
                    url: url.to_string(),
                    message: format!("failed to initialize AES-192-CTR: {source}"),
                })?;
            cipher.apply_keystream(&mut plaintext);
        }
        32 => {
            let mut cipher =
                Aes256Ctr::new_from_slices(&aes_key, iv).map_err(|source| Error::Crypto {
                    url: url.to_string(),
                    message: format!("failed to initialize AES-256-CTR: {source}"),
                })?;
            cipher.apply_keystream(&mut plaintext);
        }
        size => {
            return Err(Error::Crypto {
                url: url.to_string(),
                message: format!("unsupported AES key size: {size}"),
            });
        }
    }

    while plaintext.last().is_some_and(u8::is_ascii_whitespace) {
        plaintext.pop();
    }
    Ok(plaintext)
}

pub fn encoded_public_key(public_key: &RsaPublicKey, url: &str) -> Result<String> {
    let pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|source| Error::Crypto {
            url: url.to_string(),
            message: format!("failed to encode RSA public key: {source}"),
        })?;
    Ok(BASE64.encode(pem.as_bytes()))
}
