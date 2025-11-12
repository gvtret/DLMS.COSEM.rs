
use aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Error, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::vec::Vec;

#[derive(Debug)]
pub enum SecurityError {
    InvalidKeyLength,
    EncryptionError,
    DecryptionError,
}

impl From<Error> for SecurityError {
    fn from(_: Error) -> Self {
        SecurityError::DecryptionError
    }
}

type HmacSha256 = Hmac<Sha256>;

pub fn lls_authenticate(password: &[u8], challenge: &[u8]) -> Result<Vec<u8>, SecurityError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(password).map_err(|_| SecurityError::InvalidKeyLength)?;
    mac.update(challenge);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(code_bytes.to_vec())
}

pub fn hls_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SecurityError::InvalidKeyLength)?;
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| SecurityError::EncryptionError)?;
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce);
    encrypted_data.extend_from_slice(&ciphertext);
    Ok(encrypted_data)
}

pub fn hls_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SecurityError::InvalidKeyLength)?;
    let (nonce_slice, ciphertext) = data.split_at(12);
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(nonce_slice);
    let plaintext = cipher.decrypt(&nonce, ciphertext)?;
    Ok(plaintext)
}
