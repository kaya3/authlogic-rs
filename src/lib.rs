mod app;
mod errors;
mod hashing;
pub mod mail;
mod maybe_auth;
mod middleware;
mod secret;
mod sessions;
mod token_actions;
mod tokens;
mod users;

pub use app::{
    App,
    AppConfig,
    AppDb,
    AppMailer,
    AppTypes,
};
pub use errors::Error;
pub use maybe_auth::{
    Auth,
    MaybeAuth,
    maybe_auth_from_request,
    require_auth_from_request,
    require_user_from_request,
};
pub use middleware::middleware;
pub use secret::{
    PasswordHash,
    Secret,
};
pub use sessions::{
    SessionData,
    login,
};
pub use users::{
    UserData,
    UserID,
    UserState,
    change_password,
    register_new_user,
    register_new_user_without_password,
    register_new_user_with_temporary_password,
    request_password_reset,
};

/// NIST recommend to require a minimum password length of 8 characters.
///
/// NIST also recommend **not** to require passwords with certain compositions
/// (e.g. upper and lowercase letters, special characters, etc.).
///
/// See https://pages.nist.gov/800-63-3/sp800-63b.html#5111-memorized-secret-authenticators
pub const NIST_MINIMUM_PASSWORD_LENGTH: usize = 8;
