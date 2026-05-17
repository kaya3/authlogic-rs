use password_hash::{PasswordVerifier, phc};

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

/// Checks a password against a stored password hash, returning `true` if the
/// password is correct, and `false` if it is incorrect or if the stored hash
/// is missing (meaning no password is associated with the user account).
/// 
/// This function is used for passwords when logging in, and for challenge
/// codes when registering a new account.
/// 
/// Returns an error if the stored hash is invalid.
pub(crate) fn check_password(stored_hash: &PasswordHash, given_password: &Secret) -> Result<bool, Error> {
    let Some(stored_hash) = stored_hash.expose() else {
        return Ok(false);
    };
    
    let hash = phc::PasswordHash::new(stored_hash)
        .map_err(Error::StoredPasswordHash)?;

    let algs: &[&dyn PasswordVerifier<phc::PasswordHash>] = &[
        &argon2::Argon2::default(),
        #[cfg(feature = "pbkdf2")] &pbkdf2::Pbkdf2::default(),
        #[cfg(feature = "scrypt")] &scrypt::Scrypt::default(),
    ];

    let given_password_bytes = given_password.expose().as_bytes();
    for alg in algs {
        use password_hash::Error as E;

        let result = alg.verify_password(given_password_bytes, &hash);
        match result {
            Ok(()) => return Ok(true),
            Err(E::PasswordInvalid) => return Ok(false),
            Err(_) => continue,
        }
    }

    Ok(false)
}

/// Computes a password hash for the given password, which can be stored in the
/// database. A strong password hashing algorithm with a salt is used.
///
/// This function cannot be used to compare a password against a stored hash;
/// instead, use the `check_password` function.
pub(crate) fn generate_password_hash(new_password: &Secret) -> Result<PasswordHash, Error> {
    use argon2::{Argon2, PasswordHasher};

    let salt = phc::Salt::from_rng(&mut rand::rng());
    let hash = Argon2::default()
        .hash_password_with_salt(new_password.expose().as_bytes(), &salt)
        .map_err(Error::NewPasswordHash)?;
    
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
    let mut bytes = [0u8; N];
    _generate_base64_token(&mut bytes)
}

fn _generate_base64_token(buffer: &mut [u8]) -> Secret {
    use rand::{rng, RngExt};
    rng().fill(buffer);
    Secret(base64_encode(buffer))
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
        check_password, Secret,
    };

    #[test]
    fn test_password_hash() {
        let password = Secret("example".to_string());
        let wrong_password = Secret("something else".to_string());
        let hash = generate_password_hash(&password).unwrap();

        assert!(check_password(&hash, &password).expect("Correct password should verify"));
        assert!(!check_password(&hash, &wrong_password).expect("Incorrect password should at least compare"));
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
