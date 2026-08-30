//! Password hashing and token digests (spec §12 rule 7).
//!
//! argon2id with OWASP-recommended parameters. Verification is constant-time and
//! deliberately *not* short-circuited when the account does not exist: a login
//! form that answers faster for unknown usernames is a user enumeration oracle.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use unihelm_core::{ErrorCode, UnihelmError};

/// OWASP's argon2id baseline: 19 MiB, 2 iterations, 1 lane.
///
/// Chosen to stay honest on the 1 GB VPS the panel targets — a bigger memory
/// cost would make a login spike compete with the sites we are hosting.
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// A hash of this string is verified when the username is unknown, so a failed
/// login costs the same whether or not the account exists.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$\
                          GpZ3sK8VvTfKuP1bqO4qHtVvXvvKXG0kkeVEHbBFDrE";

fn argon2() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
        .expect("the compiled-in argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password for storage.
pub fn hash_password(password: &str) -> Result<String, UnihelmError> {
    check_strength(password)?;
    let salt = SaltString::generate(&mut rand::thread_rng());
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| UnihelmError::internal(format!("password hashing failed: {e}")))
}

/// Verify a password against a stored hash.
///
/// A malformed stored hash returns `false` rather than an error: the account
/// simply cannot be logged into, which is the safe direction.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        tracing::error!("a stored password hash is malformed; login refused");
        return false;
    };
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Burn the same CPU a real verification would, so timing does not reveal
/// whether the username exists.
pub fn verify_dummy(password: &str) {
    let _ = verify_password(password, DUMMY_HASH);
}

/// The panel's password policy.
///
/// Length beats composition rules: a 12-character passphrase is stronger than
/// `P@ssw0rd!` and far likelier to be remembered rather than reused.
pub fn check_strength(password: &str) -> Result<(), UnihelmError> {
    const MIN: usize = 12;
    // argon2 itself has no practical ceiling, but an unbounded input is free CPU
    // for an attacker.
    const MAX: usize = 1024;

    if password.chars().count() < MIN {
        return Err(UnihelmError::new(
            ErrorCode::PasswordTooWeak,
            format!("password must be at least {MIN} characters"),
        )
        .with_field("password"));
    }
    if password.len() > MAX {
        return Err(
            UnihelmError::new(ErrorCode::PasswordTooWeak, "password is too long")
                .with_field("password"),
        );
    }
    Ok(())
}

/// Generate a cryptographically random token, returned as lowercase hex.
///
/// Used for session cookies, CSRF tokens and API keys. 32 bytes = 256 bits.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The digest stored in place of a token.
///
/// Session ids and API tokens are stored hashed so a leaked database backup is
/// not a set of live credentials. SHA-256 (not argon2) is right here: the input
/// is already 256 bits of entropy, so there is nothing to slow-hash against.
pub fn token_digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("Correct horse battery staple", &hash));
        assert!(!verify_password("", &hash));
    }

    #[test]
    fn hashes_are_salted_so_equal_passwords_differ() {
        let a = hash_password("correct horse battery staple").unwrap();
        let b = hash_password("correct horse battery staple").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn stored_hash_records_argon2id_and_our_parameters() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "must be argon2id, got: {hash}"
        );
        assert!(
            hash.contains("m=19456"),
            "memory cost must be recorded: {hash}"
        );
        assert!(hash.contains("t=2"));
    }

    #[test]
    fn policy_is_length_first() {
        assert!(check_strength("short").is_err());
        assert!(check_strength("elevenchars").is_err());
        assert!(check_strength("twelvechars!").is_ok());
        // A long passphrase of ordinary words is fine; no composition theatre.
        assert!(check_strength("my very long passphrase with spaces").is_ok());
        assert!(check_strength(&"a".repeat(2000)).is_err());
    }

    #[test]
    fn weak_passwords_never_reach_a_hash() {
        let err = hash_password("123").unwrap_err();
        assert_eq!(err.code, ErrorCode::PasswordTooWeak);
    }

    #[test]
    fn a_malformed_stored_hash_refuses_rather_than_panics() {
        assert!(!verify_password("anything", "not-a-hash"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn dummy_verification_is_a_real_argon2_run() {
        // If DUMMY_HASH stopped parsing, the timing defence would silently
        // become a no-op, so assert the shape here.
        assert!(
            PasswordHash::new(DUMMY_HASH).is_ok(),
            "the dummy hash must stay a valid PHC string"
        );
        verify_dummy("whatever");
    }

    #[test]
    fn tokens_are_random_and_hex() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digests_are_stable_and_one_way() {
        let token = generate_token();
        assert_eq!(token_digest(&token), token_digest(&token));
        assert_ne!(token_digest(&token), token);
        assert_eq!(token_digest(&token).len(), 64);
    }
}
