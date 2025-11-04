
use aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use heapless::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn lls_authenticate(password: &[u8], challenge: &[u8]) -> Vec<u8, 32> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password).unwrap();
    mac.update(challenge);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Vec::from_slice(&code_bytes).unwrap()
}

pub fn hls_encrypt(data: &[u8], key: &[u8]) -> Vec<u8, 2048> {
    let key = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(key);
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).unwrap();
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce).unwrap();
    encrypted_data.extend_from_slice(&ciphertext).unwrap();
    encrypted_data
}

pub fn hls_decrypt(data: &[u8], key: &[u8]) -> Vec<u8, 2048> {
    let key = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(key);
    let (nonce, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).unwrap();
    Vec::from_slice(&plaintext).unwrap()
}
