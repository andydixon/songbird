use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use pqcrypto::kem::kyber1024;
use sha3::Sha3_256;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur in the Songbird-like machine and configuration.
#[derive(Debug, Error)]
pub enum SongbirdError {
    #[error("Character '{0}' not in character set.")]
    CharNotInSet(char),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Key exchange error: {0}")]
    KeyExchangeError(String),
    #[error("HKDF expansion error")]
    HkdfError,
}

/// The CharacterSet defines the domain of characters for the Songbird-like machine.
pub struct CharacterSet {
    chars: Vec<char>,
    index_map: HashMap<char, usize>,
}

impl CharacterSet {
    pub fn new(chars: &[char]) -> Result<Self, SongbirdError> {
        let mut index_map = HashMap::new();
        for (i, &c) in chars.iter().enumerate() {
            if index_map.contains_key(&c) {
                return Err(SongbirdError::ConfigError("Duplicate char in set".into()));
            }
            index_map.insert(c, i);
        }
        Ok(CharacterSet {
            chars: chars.to_vec(),
            index_map,
        })
    }

    pub fn size(&self) -> usize {
        self.chars.len()
    }

    pub fn char_to_index(&self, c: char) -> Result<usize, SongbirdError> {
        self.index_map
            .get(&c)
            .copied()
            .ok_or(SongbirdError::CharNotInSet(c))
    }

    pub fn index_to_char(&self, i: usize) -> char {
        self.chars[i]
    }
}

/// A Nugget trait for the Songbird-like machine.
pub trait Nugget {
    fn step(&mut self);
    fn forward(&self, c_idx: usize) -> usize;
    fn backward(&self, c_idx: usize) -> usize;
    fn at_meditation(&self) -> bool;
}

/// A standard nugget implementation.
pub struct StandardNugget {
    wiring: Vec<usize>,
    inverse_wiring: Vec<usize>,
    meditation_positions: Vec<usize>,
    position: usize,
    ring_setting: usize,
    size: usize,
}

impl StandardNugget {
    pub fn new(
        charset: &CharacterSet,
        wiring_chars: &[char],
        meditation_chars: &[char],
        initial_char: char,
        ring_setting: usize,
    ) -> Result<Self, SongbirdError> {
        let size = charset.size();
        if wiring_chars.len() != size {
            return Err(SongbirdError::ConfigError("Wiring must cover entire set".into()));
        }

        let mut wiring = vec![0; size];
        let mut used = vec![false; size];
        for (i, &wc) in wiring_chars.iter().enumerate() {
            let idx = charset.char_to_index(wc)?;
            if used[idx] {
                return Err(SongbirdError::ConfigError("Duplicate character in wiring".into()));
            }
            used[idx] = true;
            wiring[i] = idx;
        }

        if used.iter().any(|&u| !u) {
            return Err(SongbirdError::ConfigError("Not all chars used in wiring".into()));
        }

        let mut inverse_wiring = vec![0; size];
        for (i, &mapped) in wiring.iter().enumerate() {
            inverse_wiring[mapped] = i;
        }

        let meditation_positions = meditation_chars
            .iter()
            .map(|&c| charset.char_to_index(c))
            .collect::<Result<Vec<_>, _>>()?;

        let position = charset.char_to_index(initial_char)?;
        let ring_setting = (ring_setting - 1) % size;

        Ok(Self {
            wiring,
            inverse_wiring,
            meditation_positions,
            position,
            ring_setting,
            size,
        })
    }
}

impl Nugget for StandardNugget {
    fn step(&mut self) {
        self.position = (self.position + 1) % self.size;
    }

    fn forward(&self, c_idx: usize) -> usize {
        let size = self.size;
        let shifted = (c_idx + self.position + size - self.ring_setting) % size;
        let mapped = self.wiring[shifted];
        (mapped + size - self.position + self.ring_setting) % size
    }

    fn backward(&self, c_idx: usize) -> usize {
        let size = self.size;
        let shifted = (c_idx + self.position + size - self.ring_setting) % size;
        let mapped = self.inverse_wiring[shifted];
        (mapped + size - self.position + self.ring_setting) % size
    }

    fn at_meditation(&self) -> bool {
        self.meditation_positions.contains(&self.position)
    }
}

/// Sidequest trait.
pub trait Sidequest {
    fn reflect(&self, c_idx: usize) -> usize;
}

/// Standard sidequest implementation.
pub struct StandardSidequest {
    wiring: Vec<usize>,
}

impl StandardSidequest {
    pub fn new(charset: &CharacterSet, wiring_chars: &[char]) -> Result<Self, SongbirdError> {
        let size = charset.size();
        if wiring_chars.len() != size {
            return Err(SongbirdError::ConfigError("Sidequest must cover entire set".into()));
        }
        let mut wiring = vec![0; size];
        let mut used = vec![false; size];
        for (i, &wc) in wiring_chars.iter().enumerate() {
            let idx = charset.char_to_index(wc)?;
            if used[idx] {
                return Err(SongbirdError::ConfigError("Duplicate in sidequest".into()));
            }
            used[idx] = true;
            wiring[i] = idx;
        }
        if used.iter().any(|&u| !u) {
            return Err(SongbirdError::ConfigError("Not all chars used in sidequest".into()));
        }
        Ok(StandardSidequest { wiring })
    }
}

impl Sidequest for StandardSidequest {
    fn reflect(&self, c_idx: usize) -> usize {
        self.wiring[c_idx]
    }
}

/// Exchanger swaps pairs of characters.
pub struct Exchanger {
    mapping: Vec<usize>,
}

impl Exchanger {
    pub fn new(charset: &CharacterSet, pairs: &[(char, char)]) -> Result<Self, SongbirdError> {
        let size = charset.size();
        let mut mapping: Vec<usize> = (0..size).collect();
        for &(a, b) in pairs {
            let a_idx = charset.char_to_index(a)?;
            let b_idx = charset.char_to_index(b)?;
            let temp = mapping[a_idx];
            mapping[a_idx] = mapping[b_idx];
            mapping[b_idx] = temp;
        }
        Ok(Exchanger { mapping })
    }

    fn plug(&self, c_idx: usize) -> usize {
        self.mapping[c_idx]
    }
}

/// The Songbird Machine structure.
pub struct SongbirdMachine<R1: Nugget, R2: Nugget, R3: Nugget, Ref: Sidequest> {
    charset: CharacterSet,
    nugget_right: R1,
    nugget_middle: R2,
    nugget_left: R3,
    sidequest: Ref,
    exchanger: Exchanger,
}

impl<R1: Nugget, R2: Nugget, R3: Nugget, Ref: Sidequest> SongbirdMachine<R1, R2, R3, Ref> {
    pub fn new(
        charset: CharacterSet,
        nugget_right: R1,
        nugget_middle: R2,
        nugget_left: R3,
        sidequest: Ref,
        exchanger: Exchanger,
    ) -> Self {
        Self {
            charset,
            nugget_right,
            nugget_middle,
            nugget_left,
            sidequest,
            exchanger,
        }
    }

    fn step_nuggets(&mut self) {
        let right_at_meditation = self.nugget_right.at_meditation();
        let middle_at_meditation = self.nugget_middle.at_meditation();

        self.nugget_right.step();

        if right_at_meditation {
            self.nugget_middle.step();
        }

        if middle_at_meditation {
            self.nugget_left.step();
        }
    }

    pub fn encrypt_char(&mut self, c: char) -> Result<char, SongbirdError> {
        let c_idx = match self.charset.char_to_index(c) {
            Ok(i) => i,
            Err(_) => {
                // If char not in set, leave it unchanged
                return Ok(c);
            }
        };

        self.step_nuggets();

        let x = self.exchanger.plug(c_idx);
        let x = self.nugget_right.forward(x);
        let x = self.nugget_middle.forward(x);
        let x = self.nugget_left.forward(x);

        let x = self.sidequest.reflect(x);

        let x = self.nugget_left.backward(x);
        let x = self.nugget_middle.backward(x);
        let x = self.nugget_right.backward(x);

        let x = self.exchanger.plug(x);

        Ok(self.charset.index_to_char(x))
    }

    pub fn encrypt_message(&mut self, msg: &str) -> Result<String, SongbirdError> {
        msg.chars().map(|c| self.encrypt_char(c)).collect()
    }
}

/// Derive a key and IV from a shared secret using HKDF-SHA3.
fn derive_key_iv(shared_secret: &[u8]) -> Result<([u8; 32], [u8; 12]), SongbirdError> {
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    hk.expand(b"chacha-key", &mut key)
        .map_err(|_| SongbirdError::HkdfError)?;
    hk.expand(b"chacha-iv", &mut iv)
        .map_err(|_| SongbirdError::HkdfError)?;
    Ok((key, iv))
}

/// Example function to show how to set up and use the PQ + Songbird + ChaCha20 layer.
/// It returns the ciphertext and the plaintext after decryption as (ciphertext, decrypted).
pub fn pq_songbird_round_trip(plaintext: &str) -> Result<(String, String), SongbirdError> {
    // Post-quantum key exchange (Kyber)
    let (pk, sk) = kyber1024::keypair();
    let (ciphertext, shared_secret_alice) = kyber1024::encapsulate(&pk);
    let shared_secret_bob = kyber1024::decapsulate(&ciphertext, &sk)
        .map_err(|_| SongbirdError::KeyExchangeError("Decapsulation failed".to_string()))?;

    // Both parties share the same secret
    assert_eq!(shared_secret_alice, shared_secret_bob);
    let shared_secret = shared_secret_alice;

    // Derive key and IV for ChaCha20
    let (chacha_key, chacha_iv) = derive_key_iv(&shared_secret)?;

    // Setup ChaCha20
    let mut encrypt_cipher = ChaCha20::new(&chacha_key.into(), &chacha_iv.into());

    // Define character set for Songbird
    let chars: Vec<char> = (32u8..=126u8).map(|b| b as char).collect();
    let charset = CharacterSet::new(&chars)?;

    // Create a simple nugget by rotating chars by 1
    let mut wiring_chars = chars.clone();
    wiring_chars.rotate_left(1);
    let nugget_right = StandardNugget::new(&charset, &wiring_chars, &['!'], ' ', 1)?;
    let nugget_middle = StandardNugget::new(&charset, &wiring_chars, &['@'], ' ', 1)?;
    let nugget_left = StandardNugget::new(&charset, &wiring_chars, &['#'], ' ', 1)?;

    // Sidequest: reverse the charset
    let mut sidequest_chars = chars.clone();
    sidequest_chars.reverse();
    let sidequest = StandardSidequest::new(&charset, &sidequest_chars)?;

    let exchanger = Exchanger::new(&charset, &[('A','Z')])?;

    // Build the Songbird machine for encryption
    let mut songbird = SongbirdMachine::new(
        charset,
        nugget_right,
        nugget_middle,
        nugget_left,
        sidequest,
        exchanger,
    );

    // 1. Encrypt with ChaCha20
    let mut intermediate = plaintext.as_bytes().to_vec();
    encrypt_cipher.apply_keystream(&mut intermediate);

    // 2. Pass through Songbird
    let ciphertext = songbird.encrypt_message(&String::from_utf8_lossy(&intermediate))?;

    // Now decrypt
    // Rebuild the charset and machines
    let chars: Vec<char> = (32u8..=126u8).map(|b| b as char).collect();
    let charset = CharacterSet::new(&chars)?;

    let nugget_right = StandardNugget::new(&charset, &wiring_chars, &['!'], ' ', 1)?;
    let nugget_middle = StandardNugget::new(&charset, &wiring_chars, &['@'], ' ', 1)?;
    let nugget_left = StandardNugget::new(&charset, &wiring_chars, &['#'], ' ', 1)?;
    let sidequest = StandardSidequest::new(&charset, &sidequest_chars)?;
    let exchanger = Exchanger::new(&charset, &[('A','Z')])?;
    let mut songbird_decrypt = SongbirdMachine::new(
        charset,
        nugget_right,
        nugget_middle,
        nugget_left,
        sidequest,
        exchanger,
    );

    // Inverse steps for decrypt:
    // 1. Pass ciphertext through Songbird
    let mut songbird_dec = songbird_decrypt.encrypt_message(&ciphertext)?.into_bytes();

    // 2. Apply ChaCha20 again with same key/iv to get plaintext back
    let mut decrypt_cipher = ChaCha20::new(&chacha_key.into(), &chacha_iv.into());
    decrypt_cipher.apply_keystream(&mut songbird_dec);

    let decrypted = String::from_utf8_lossy(&songbird_dec).to_string();

    Ok((ciphertext, decrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_songbird_round_trip() -> Result<(), SongbirdError> {
        let plaintext = "Hello PQ Songbird World!";
        let (cipher, dec) = pq_songbird_round_trip(plaintext)?;
        assert_eq!(dec, plaintext);
        assert_ne!(cipher, plaintext);
        Ok(())
    }
}
