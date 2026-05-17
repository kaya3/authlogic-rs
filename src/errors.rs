use actix_web::http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Indicates that the user is authenticated but cannot continue until they
    /// verify their email address. This can happen if a user registers a new
    /// account with a password, then uses their password to log in before
    /// completing the email verification challenge.
    #[error("Email address is not verified")]
    EmailNotVerified,

    /// Indicates that the user tried to complete an email challenge, but the
    /// code in their challenge link is not correct. The challenge might
    /// already have been completed, or expired, or it never existed.
    #[error("Incorrect challenge code")]
    IncorrectChallengeCode,

    /// Indicates that the user is not authenticated in a context where they
    /// need to be.
    #[error("User is not authenticated")]
    NotAuthenticated,

    /// Indicates that the user is authenticated but cannot continue until they
    /// choose a new password. This can happen if a new user is created with a
    /// temporary password, or the user completed a password reset challenge.
    #[error("User is required to change their password")]
    RequirePasswordChange,

    /// Indicates that the user is authenticated but cannot continue, because
    /// their account has been suspended.
    #[error("User is suspended")]
    UserIsSuspended,

    /// Internal error which occurs when an authenticated user attempts to
    /// reauthenticate, but when `AppDb::get_user_data_by_id` was called to
    /// fetch the user's password, no record was returned.
    /// 
    /// This either indicates a logic error in your `AppDb` implementation, or
    /// a race condition in which the user is deleted after the session cookie
    /// is verified but before the reauthentication is checked.
    #[error("User data query failed for id = {user_id}")]
    UserDataQueryFailed {user_id: i64},

    /// Internal error which occurs when serializing or deserializing challenge
    /// data.
    #[error("Corrupted challenge data")]
    Serde(#[source] serde_json::Error),
    
    /// Internal error which occurs when hashing a new password.
    #[error("Failed to generate new password hash")]
    NewPasswordHash(#[source] password_hash::Error),
    
    /// Internal error which occurs when verifying a password. This could
    /// indicate, for example, that a hash stored in the database is in the
    /// wrong format, or uses an unsupported algorithm.
    #[error("Failed to parse stored password hash")]
    StoredPasswordHash(#[source] password_hash::phc::Error),
}

impl Error {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::UserIsSuspended
            | Self::IncorrectChallengeCode
            | Self::EmailNotVerified
            | Self::RequirePasswordChange
            | Self::NotAuthenticated => StatusCode::UNAUTHORIZED,

            Self::UserDataQueryFailed {..}
            | Self::NewPasswordHash(_)
            | Self::StoredPasswordHash(_)
            | Self::Serde(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn as_app_err<T, E: From<Self>>(self) -> Result<T, E> {
        Err(E::from(self))
    }
}
