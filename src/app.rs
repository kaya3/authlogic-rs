use crate::{
    errors::Error,
    mail::{Challenge, ChallengeData, Notification},
    secret::{PasswordHash, Secret},
    sessions::SessionData,
    users::{UserData, UserID},
    NIST_MINIMUM_PASSWORD_LENGTH,
};

pub trait App: AppConfig + AppDb + AppMailer + AppTypes + Clone + 'static {
    /// Returns the current time.
    fn time_now(&self) -> Self::DateTime;
}

pub trait AppTypes: Sized {
    /// The type of a numeric ID in the database; usually `i64`, `i32`, etc.
    type ID: Into<i64> + TryFrom<i64> + Eq + Copy + std::fmt::Display;

    /// The type used to represent a date and time in the application.
    type DateTime: Copy + Ord + core::ops::Add<std::time::Duration, Output = Self::DateTime>;

    /// The type of a user in the application.
    type User: UserID<Self::ID> + Clone;

    /// A type representing custom email challenges which can be issued by the
    /// application. Use `authlib::mail::NoCustomChallenges` if there are none.
    type CustomChallenge: serde::Serialize + for<'de> serde::Deserialize<'de>;

    /// A type representing an application error. This must support conversion
    /// from `authlib::Error`.
    type Error: From<Error> + actix_web::ResponseError;
}

/// This trait defines functions which provide configuration parameters to the
/// authentication library.
#[allow(unused)]
pub trait AppConfig {
    /// Returns the minimum password length.
    ///
    /// Default is 8, as recommended by NIST.
    fn minimum_password_length(&self) -> usize {
        NIST_MINIMUM_PASSWORD_LENGTH
    }

    /// Returns the number of hours after which a challenge expires, if it is
    /// not completed.
    ///
    /// Default is 1 day.
    fn challenge_expire_after_hours(&self) -> u64 {
        1 * 24
    }

    /// Returns the number of hours after which a session expires, if it is not
    /// renewed.
    ///
    /// Default is 90 days.
    fn session_expire_after_hours(&self) -> u64 {
        90 * 24
    }

    /// Returns the number of hours after which a session should be renewed, if
    /// it has not expired yet.
    ///
    /// Default is 2 days.
    fn session_renew_after_hours(&self) -> u64 {
        2 * 24
    }

    /// Returns the name of the cookie which holds the session token.
    ///
    /// Default is `"session"``.
    fn session_token_cookie_name(&self) -> &str {
        "session"
    }

    /// Indicates whether a `Same-Site: strict` header should be sent with the
    /// session cookie. If `false`, a `Same-Site: lax` header will be sent
    /// instead.
    ///
    /// Default is `false`.
    fn session_token_cookie_same_site_strict(&self) -> bool {
        false
    }
}

/// This trait defines functions which will be used by the authentication
/// library to store and retrieve data about users, sessions and challenges.
#[trait_variant::make(Send)]
pub trait AppDb: AppTypes {
    /// Gets a user's data, including their password hash and active state, by
    /// their id.
    ///
    /// Returns `None` if there is no user with that identifier.
    async fn get_user_data_by_id(
        &self,
        user_id: Self::ID,
    ) -> Result<Option<UserData<Self>>, Self::Error>;

    /// Gets a user's data, including their password hash and active state, by
    /// their identifier (e.g. username or email).
    ///
    /// Returns `None` if there is no user with that identifier.
    async fn get_user_data_by_identifier(
        &self,
        user_identifier: &str,
    ) -> Result<Option<UserData<Self>>, Self::Error>;

    /// Inserts a new user, returning the new user's unique id.
    async fn insert_user(
        &self,
        user_data: &UserData<Self>,
    ) -> Result<Self::ID, Self::Error>;

    /// Updates an unverified user to mark them as verified.
    async fn verify_user(&self, user: &Self::User) -> Result<(), Self::Error>;

    /// Updates a user's stored password hash, also recording whether they are
    /// subsequently required to change their password.
    async fn update_password(
        &self,
        user: &Self::User,
        password_hash: PasswordHash,
        then_require_change: bool,
    ) -> Result<(), Self::Error>;

    /// Deletes a user by their id, if they exist. It is not an error to
    /// attempt to delete a non-existent user.
    async fn delete_user(&self, user_id: Self::ID) -> Result<(), Self::Error>;

    /// Gets the data for a session, including the user, whether the user is
    /// active, the session token hash, and the session expiry time.
    ///
    /// Returns `None` if there is no session with that id.
    async fn get_session_by_id(
        &self,
        session_id: Self::ID,
    ) -> Result<Option<SessionData<Self>>, Self::Error>;

    /// Inserts a new session, returning the new session's unique id.
    async fn insert_session(
        &self,
        user: &Self::User,
        token_hash: Secret,
        expires: Self::DateTime,
    ) -> Result<Self::ID, Self::Error>;

    /// Updates a session's stored token hash and expiry time.
    async fn update_session_by_id(
        &self,
        session_id: Self::ID,
        new_token_hash: Secret,
        expires: Self::DateTime,
    ) -> Result<(), Self::Error>;

    /// Deletes a session by its id, if it exists. It is not an error to
    /// attempt to delete a non-existent session.
    async fn delete_session_by_id(&self, session_id: Self::ID) -> Result<(), Self::Error>;

    /// Gets the data for a challenge, including the user, the challenge type,
    /// the challenge code hash, and the challenge expiry time.
    ///
    /// Returns `None` if there is no challenge with that id.
    async fn get_challenge_by_id(
        &self,
        challenge_id: Self::ID,
    ) -> Result<Option<ChallengeData<Self>>, Self::Error>;

    /// Inserts a new challenge, returning the new challenge's id.
    async fn insert_challenge(
        &self,
        user: &Self::User,
        challenge: &str,
        code_hash: Secret,
        expires: Self::DateTime,
    ) -> Result<Self::ID, Self::Error>;

    /// Deletes a challenge by its id, if it exists. It is not an error to
    /// attempt to delete a non-existent challenge.
    async fn delete_challenge_by_id(&self, challenge_id: Self::ID) -> Result<(), Self::Error>;
}

/// This trait defines functions which will be used by the authentication
/// library to send email notifications and challenges to users.
#[trait_variant::make(Send)]
pub trait AppMailer: AppTypes {
    /// Sends an email notification to the given user.
    async fn send_notification(
        &self,
        user: &Self::User,
        notification: Notification,
    ) -> Result<(), Self::Error>;

    /// Sends an email message to the given user, with a link to complete a
    /// challenge. The link must match a route which invokes `complete_challenge(code)`.
    async fn send_challenge(
        &self,
        user: &Self::User,
        challenge: Challenge<Self>,
        code: Secret,
    ) -> Result<(), Self::Error>;
}
