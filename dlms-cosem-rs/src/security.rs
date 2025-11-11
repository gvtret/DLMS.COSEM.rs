
use aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Error, Nonce};
use heapless::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, PartialEq, Eq)]
pub enum SecurityError {
    InvalidKeyLength,
    EncryptionError,
    DecryptionError,
    AuthenticationError,
}

impl From<Error> for SecurityError {
    fn from(_: Error) -> Self {
        SecurityError::DecryptionError
    }
}

type HmacSha256 = Hmac<Sha256>;

pub fn lls_authenticate(password: &[u8], challenge: &[u8]) -> Result<Vec<u8, 32>, SecurityError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(password).map_err(|_| SecurityError::InvalidKeyLength)?;
    mac.update(challenge);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(Vec::from_slice(&code_bytes).unwrap())
}

pub fn hls_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8, 2048>, SecurityError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SecurityError::InvalidKeyLength)?;
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| SecurityError::EncryptionError)?;
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce).unwrap();
    encrypted_data.extend_from_slice(&ciphertext).unwrap();
    Ok(encrypted_data)
}

pub fn hls_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8, 2048>, SecurityError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SecurityError::InvalidKeyLength)?;
    let (nonce_slice, ciphertext) = data.split_at(12);
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(nonce_slice);
    let plaintext = cipher.decrypt(&nonce, ciphertext)?;
    Ok(Vec::from_slice(&plaintext).unwrap())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_lls_authenticate() {
        let password = b"password";
        let challenge = b"challenge";
        let expected_response = lls_authenticate(password, challenge).unwrap();

        let correct_response = lls_authenticate(password, challenge).unwrap();
        assert_eq!(expected_response, correct_response);

        let wrong_password = b"wrong_password";
        let wrong_response = lls_authenticate(wrong_password, challenge).unwrap();
        assert_ne!(expected_response, wrong_response);
    }
}
