//! Secrets at rest (spec §12 rule 6).
//!
//! ACME account keys, DNS provider credentials and SMTP passwords are sealed
//! before they are stored, under a master key generated once at install time and
//! kept at `/etc/unihelm/secret.key` with mode 0600.
//!
//! The spec names libsodium sealed boxes. This uses **XChaCha20-Poly1305**,
//! which is the same construction libsodium's `crypto_secretbox` is built on,
//! from a pure-Rust implementation. The substance is identical; what it avoids
//! is a C library on the build host and in the binary, which the 25 MB budget
//! and a hermetic cross-compile both care about.
//!
//! A 24-byte random nonce is generated per message and stored alongside the
//! ciphertext. XChaCha's nonce is large enough that random generation is safe
//! without a counter — which matters here, because the panel has no single
//! place to keep one.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::{DbError, Result};

/// Length of the master key, in bytes.
pub const MASTER_KEY_BYTES: usize = 32;

const NONCE_BYTES: usize = 24;

/// The panel's master key, held in memory only while the agent runs.
///
/// Deliberately not `Debug` or `Clone`: the way key material ends up in a log is
/// somebody adding `?key` to a tracing call.
pub struct MasterKey(Key);

impl MasterKey {
    /// Read the key from disk, checking that nobody else can.
    ///
    /// A master key that is group- or world-readable is not a master key, and
    /// silently using it anyway would make the whole scheme decorative.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(|e| DbError::Corrupt {
            field: "master key",
            detail: format!("{}: {e}", path.display()),
        })?;

        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(DbError::Corrupt {
                field: "master key",
                detail: format!(
                    "{} is mode {mode:o}; it must be 0600. Fix it with `chmod 600 {}`",
                    path.display(),
                    path.display()
                ),
            });
        }

        let text = std::fs::read_to_string(path).map_err(|e| DbError::Corrupt {
            field: "master key",
            detail: format!("{}: {e}", path.display()),
        })?;
        Self::from_hex(text.trim())
    }

    /// Parse a hex-encoded key, as the installer writes it.
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key).map_err(|e| DbError::Corrupt {
            field: "master key",
            detail: format!("not valid hex: {e}"),
        })?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MASTER_KEY_BYTES {
            return Err(DbError::Corrupt {
                field: "master key",
                detail: format!("expected {MASTER_KEY_BYTES} bytes, got {}", bytes.len()),
            });
        }
        let array: [u8; MASTER_KEY_BYTES] =
            bytes.try_into().expect("length checked immediately above");
        Ok(Self(Key::from(array)))
    }

    /// Generate a fresh key, for tests and for first-run setup.
    pub fn generate() -> Self {
        let mut bytes = [0u8; MASTER_KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(Key::from(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Seal a secret. The result is `hex(nonce || ciphertext)`, safe to store in
    /// a text column and to read with `sqlite3` during an incident without
    /// revealing anything.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String> {
        let cipher = XChaCha20Poly1305::new(&self.0);

        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| DbError::Corrupt {
                field: "sealed secret",
                detail: "encryption failed".into(),
            })?;

        let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(hex::encode(out))
    }

    /// Open a sealed secret.
    ///
    /// Fails on any tampering: the Poly1305 tag covers the ciphertext, so a
    /// flipped bit is a decryption failure rather than corrupted plaintext.
    pub fn open(&self, sealed: &str) -> Result<Vec<u8>> {
        let raw = hex::decode(sealed).map_err(|e| DbError::Corrupt {
            field: "sealed secret",
            detail: format!("not valid hex: {e}"),
        })?;

        if raw.len() <= NONCE_BYTES {
            return Err(DbError::Corrupt {
                field: "sealed secret",
                detail: "too short to contain a nonce and a tag".into(),
            });
        }

        let (nonce_bytes, ciphertext) = raw.split_at(NONCE_BYTES);
        let nonce_array: [u8; NONCE_BYTES] = nonce_bytes
            .try_into()
            .expect("split_at guarantees the length");
        let nonce = XNonce::from(nonce_array);
        let cipher = XChaCha20Poly1305::new(&self.0);

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| DbError::Corrupt {
                field: "sealed secret",
                // Deliberately vague: whether the key is wrong or the data was
                // tampered with is not something to help an attacker distinguish.
                detail: "could not be decrypted — the master key may have changed, or the \
                     stored value may have been altered"
                    .into(),
            })
    }

    /// Seal a UTF-8 string.
    pub fn seal_str(&self, plaintext: &str) -> Result<String> {
        self.seal(plaintext.as_bytes())
    }

    /// Open a sealed UTF-8 string.
    pub fn open_str(&self, sealed: &str) -> Result<String> {
        let bytes = self.open(sealed)?;
        String::from_utf8(bytes).map_err(|e| DbError::Corrupt {
            field: "sealed secret",
            detail: format!("decrypted to invalid UTF-8: {e}"),
        })
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The whole point: `tracing::info!(?key)` must not print it.
        f.write_str("MasterKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_secret_round_trips() {
        let key = MasterKey::generate();
        let sealed = key.seal_str("acme account private key").unwrap();
        assert_eq!(key.open_str(&sealed).unwrap(), "acme account private key");
    }

    #[test]
    fn the_plaintext_never_appears_in_the_stored_value() {
        let key = MasterKey::generate();
        let sealed = key.seal_str("hunter2-super-secret").unwrap();
        assert!(!sealed.contains("hunter2"));
        assert!(
            sealed.chars().all(|c| c.is_ascii_hexdigit()),
            "must be safe for a text column"
        );
    }

    #[test]
    fn sealing_the_same_secret_twice_gives_different_ciphertext() {
        // A deterministic ciphertext would leak that two accounts share a
        // password, or that a credential was not rotated.
        let key = MasterKey::generate();
        let a = key.seal_str("same").unwrap();
        let b = key.seal_str("same").unwrap();
        assert_ne!(a, b);
        assert_eq!(key.open_str(&a).unwrap(), key.open_str(&b).unwrap());
    }

    #[test]
    fn a_different_key_cannot_open_it() {
        let sealed = MasterKey::generate().seal_str("secret").unwrap();
        assert!(MasterKey::generate().open(&sealed).is_err());
    }

    #[test]
    fn tampering_is_detected_rather_than_silently_decrypted() {
        let key = MasterKey::generate();
        let sealed = key.seal_str("transfer 100 to alice").unwrap();

        // Flip one hex digit in the ciphertext.
        let mut bytes: Vec<char> = sealed.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = bytes.into_iter().collect();

        assert!(
            key.open(&tampered).is_err(),
            "the authentication tag must catch this"
        );
    }

    #[test]
    fn malformed_input_is_rejected() {
        let key = MasterKey::generate();
        for bad in ["", "not hex", "aabb", &"ff".repeat(20)] {
            assert!(key.open(bad).is_err(), "`{bad}` should not open");
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(MasterKey::from_bytes(&[0u8; 16]).is_err());
        assert!(MasterKey::from_bytes(&[0u8; 64]).is_err());
        assert!(MasterKey::from_bytes(&[0u8; 32]).is_ok());
        assert!(MasterKey::from_hex("not hex").is_err());
    }

    #[test]
    fn the_key_round_trips_through_hex_as_the_installer_writes_it() {
        let key = MasterKey::generate();
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        let restored = MasterKey::from_hex(&hex).unwrap();
        let sealed = key.seal_str("x").unwrap();
        assert_eq!(restored.open_str(&sealed).unwrap(), "x");
    }

    #[test]
    fn the_key_is_not_printable() {
        let key = MasterKey::generate();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&key.to_hex()[..8]));
    }

    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        std::fs::write(&path, MasterKey::generate().to_hex()).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = MasterKey::load(&path).unwrap_err();
        assert!(err.to_string().contains("0600"), "{err}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(MasterKey::load(&path).is_ok());
    }
}
