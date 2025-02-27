use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret string (a password, session token, challenge code, or hash). Use
/// `Secret::from` to convert a `String` to a `Secret`, and `secret.expose()`
/// to access the string value where necessary.
/// 
/// Secrets are redacted in `std::fmt::Debug` displays, and are automatically
/// zeroed-out in memory when the value is dropped.
#[cfg_attr(feature = "diesel", derive(diesel_derive_newtype::DieselNewType))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(transparent))]
pub struct Secret(pub(crate) String);

/// Either a password hash, or nothing, if password authentication is not
/// available for the user. Use `PasswordHash::from` to convert a `String` or
/// `Option<String>` to a `PasswordHash`, and `hash.expose()` to access the
/// string value where necessary.
/// 
/// Secrets are redacted in `std::fmt::Debug` displays, and are automatically
/// zeroed-out in memory when the value is dropped.
#[cfg_attr(feature = "diesel", derive(diesel_derive_newtype::DieselNewType))]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(transparent))]
pub struct PasswordHash(pub(crate) Option<Secret>);

impl Secret {
    /// Make use of this secret as a `&str`. This may be needed when sending a
    /// secret to the client, or storing a hashed secret in the database.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

impl PasswordHash {
    pub const NONE: Self = Self(None);
    
    pub fn exists(&self) -> bool {
        self.0.is_some()
    }
    
    /// Make use of this password hash as a `&str`. This may be needed when
    /// storing in the database.
    pub fn expose(&self) -> Option<&str> {
        self.0.as_ref()
            .map(Secret::expose)
    }
}

impl From<String> for Secret {
    fn from(string: String) -> Self {
        Self(string)
    }
}

impl From<String> for PasswordHash {
    fn from(string: String) -> Self {
        Self(Some(Secret(string)))
    }
}

impl From<Option<String>> for PasswordHash {
    fn from(string: Option<String>) -> Self {
        Self(string.map(Secret))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[SECRET]")
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.exists() { "[SECRET]" } else { "[BLANK]" })
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)
            .map(Self::from)
    }
}

impl<'de> serde::Deserialize<'de> for PasswordHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<Secret>::deserialize(deserializer)
            .map(Self)
    }
}

// impl serde::Serialize for Secret {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         String::serialize(&self.0, serializer)
//     }
// }

// impl serde::Serialize for PasswordHash {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         Option::<Secret>::serialize(&self.0, serializer)
//     }
// }
