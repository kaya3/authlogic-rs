use argon2::Argon2;
use password_hash::{
    PasswordHasher,
    PasswordVerifier,
    SaltString,
};

use crate::{
    errors::Error,
    secret::{PasswordHash, Secret},
};

/// The number of bytes of entropy in a session token. There is not much point
/// in this being larger than 16; OWASP recommends at least 8 bytes of entropy.
/// https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy
///
/// We round up to the next multiple of three, since the token is encoded in
/// base64, so each three unencoded bytes become four encoded bytes. If the
/// number of bytes is not a multiple of 3, the encoded token will end with
/// filler characters which add no entropy.
pub const SESSION_TOKEN_BYTES: usize = 18;

/// The number of bytes of entropy in a new challenge code.
pub const CHALLENGE_CODE_BYTES: usize = 18;

/// The number of bytes of entropy in a new temporary password.
pub const TEMPORARY_PASSWORD_BYTES: usize = 9;

/// Checks a password against a stored password hash, returning `Ok` if the
/// password is correct and `Err` otherwise. This function is used for
/// passwords when logging in, and for challenge codes when registering a
/// new account.
///
/// Also returns an error if the stored hash is missing or invalid.
pub(crate) fn verify_password(stored_hash: &PasswordHash, given_password: &Secret) -> Result<(), Error> {
    let Some(stored_hash) = &stored_hash.0 else {
        return Err(Error::UserHasNoPassword);
    };
    
    let hash = password_hash::PasswordHash::new(&stored_hash.0)
        .map_err(Error::Hasher)?;

    let algs: &[&dyn PasswordVerifier] = &[&Argon2::default()];
    hash.verify_password(algs, &given_password.0)
        .map_err(|e| match e {
            password_hash::Error::Password => Error::IncorrectPassword,
            e => Error::Hasher(e),
        })
}

/// Computes a password hash for the given password, which can be stored in the
/// database. A strong password hashing algorithm with a salt is used.
///
/// This function cannot be used to compare a password against a stored hash;
/// instead, use the `check_password` function.
pub(crate) fn generate_password_hash(new_password: &Secret) -> Result<PasswordHash, Error> {
    let salt = SaltString::generate(rand::thread_rng());

    let hash = Argon2::default()
        .hash_password(new_password.0.as_bytes(), &salt)
        .map_err(Error::Hasher)?;
    
    Ok(PasswordHash(Some(Secret(hash.to_string()))))
}

/// Randomly generates a new password, returning it and its hash. A strong
/// password hashing algorithm with a salt is used.
///
/// Use the `check_password` function to compare a password against a stored
/// hash.
pub(crate) fn generate_password_and_hash() -> Result<(Secret, PasswordHash), Error> {
    let raw = generate_base64_token::<TEMPORARY_PASSWORD_BYTES>();
    let hash = generate_password_hash(&raw)?;

    Ok((raw, hash))
}

/// Generates a new random session token, and its hash. The hash should be
/// stored in the database, and the raw token should be issued to the client as
/// a cookie.
///
/// Use the `check_fast_hash` function to compare a session token against a
/// stored hash.
///
/// Returns `(token, hash)`.
pub(crate) fn generate_session_token_and_hash() -> (Secret, Secret) {
    generate_token_and_fast_hash::<SESSION_TOKEN_BYTES>()
}

/// Randomly generates a new challenge code, returning it and its hash. A
/// fast hashing algorithm is used.
///
/// Use the `check_fast_hash` function to compare a challenge code against a
/// stored hash.
pub(crate) fn generate_challenge_code_and_hash() -> (Secret, Secret) {
    generate_token_and_fast_hash::<CHALLENGE_CODE_BYTES>()
}

fn generate_token_and_fast_hash<const N: usize>() -> (Secret, Secret) {
    let raw = generate_base64_token::<N>();
    let hash = fast_hash(&raw);

    (raw, hash)
}

/// Checks whether a given raw string matches a hash, in constant time.
///
/// This function must be used when verifying a user-supplied secret against a
/// stored hash.
pub(crate) fn check_fast_hash(raw: &Secret, hash: &Secret) -> bool {
    let hash2 = fast_hash(raw);

    constant_time_eq::constant_time_eq(hash.0.as_bytes(), hash2.0.as_bytes())
}

/// Computes a fast hash of a session token or challenge code. The hash is
/// cryptographically secure, but not suitable for passwords.
///
/// A fast hash is used for session tokens, because they are authenticated on
/// every request, and a slow hash would be unacceptable for performance.
///
/// Both session tokens and challenge codes are generated randomly with high
/// entropy, not chosen by the user. They will be revoked or replaced soon
/// enough that they cannot be feasibly brute-forced by an attacker. Therefore
/// there is no real benefit to using a slow hash or salt for them.
fn fast_hash(s: &Secret) -> Secret {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&s.0);
    let hash = &hasher.finalize();
    Secret(base64_encode(hash))
}

/// Generates a random token with `N` bytes of entropy, base64-encoded. The
/// encoded token is URL-safe.
fn generate_base64_token<const N: usize>() -> Secret {
    use rand::{thread_rng, Rng};

    let mut bytes = [0u8; N];
    thread_rng().fill(&mut bytes as &mut [u8]);
    Secret(base64_encode(&bytes))
}

fn base64_encode(bytes: &[u8]) -> String {
    // Challenge codes will be used in URLs
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    URL_SAFE.encode(bytes)
}

#[cfg(test)]
mod test {
    use super::{
        check_fast_hash, fast_hash, generate_password_hash, generate_token_and_fast_hash,
        verify_password, Error, Secret,
    };

    #[test]
    fn test_password_hash() {
        let password = Secret("example".to_string());
        let wrong_password = Secret("something else".to_string());
        let hash = generate_password_hash(&password).unwrap();

        verify_password(&hash, &password).expect("Correct password should verify");
        match verify_password(&hash, &wrong_password) {
            Err(Error::IncorrectPassword) => {}
            result => panic!("Should be IncorrectPassword, was {result:?}"),
        }
    }

    #[test]
    fn test_token_hash() {
        let (raw, hash) = generate_token_and_fast_hash::<18>();

        assert_eq!(
            &hash.0,
            &fast_hash(&raw).0,
            "Hash of raw token should equal the generated hash",
        );
        assert!(check_fast_hash(&raw, &hash));
    }

    #[test]
    fn test_hash_distinct() {
        let secret1 = Secret("example".to_string());
        let secret2 = Secret("something else".to_string());
        let hash1 = fast_hash(&secret1);
        let hash2 = fast_hash(&secret2);

        assert_ne!(&hash1.0, &hash2.0, "Hashes should be distinct");
        assert!(check_fast_hash(&secret1, &hash1));
        assert!(!check_fast_hash(&secret2, &hash1));
        assert!(!check_fast_hash(&secret1, &hash2));
        assert!(check_fast_hash(&secret2, &hash2));
    }
}
