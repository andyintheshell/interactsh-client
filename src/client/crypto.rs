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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn decode_hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decrypts_nist_aes_ctr_vectors_with_rsa_oaep_keys() {
        // NIST SP 800-38A, F.5: two blocks exercise counter advancement for
        // every supported AES key size, independently of our encryption code.
        let vectors = [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94",
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5",
            ),
        ];
        let plaintext =
            decode_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let iv = decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut rng = StdRng::seed_from_u64(95);
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        for (key, ciphertext) in vectors {
            let key = decode_hex(key);
            let encrypted_key = public_key
                .encrypt(&mut rng, Oaep::new::<Sha256>(), &key)
                .unwrap();
            let mut message = iv.clone();
            message.extend_from_slice(&decode_hex(ciphertext));

            let decrypted = decrypt_message(
                &private_key,
                &BASE64.encode(encrypted_key),
                &BASE64.encode(message),
                "https://example.test/poll",
            )
            .unwrap();

            assert_eq!(decrypted, plaintext, "AES-{}-CTR", key.len() * 8);
        }
    }
}
