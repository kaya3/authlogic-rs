use std::fmt::Display;

use crate::{
    app::{App, AppTypes},
    errors::Error,
    hashing,
    mail::{Challenge, Notification, issue_challenge},
    maybe_auth::Auth,
    secret::{PasswordHash, Secret},
};

pub trait UserID<T> {
    /// Gets the user's id field.
    fn id(&self) -> T;

    /// Sets the user's id field. This is only called after inserting a new
    /// unverified user, since that is when the user receives their unique id.
    fn set_id(&mut self, new_id: T);
}

#[cfg_attr(feature = "diesel", derive(diesel::prelude::QueryableByName))]
pub struct UserData<A: AppTypes> {
    #[diesel(embed)]
    pub user: A::User,
    
    #[diesel(sql_type = diesel::sql_types::Text)]
    #[diesel(deserialize_as = String)]
    pub password_hash: PasswordHash,
    
    #[diesel(embed)]
    pub state: UserState,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow, sqlx::Type))]
#[cfg_attr(feature = "diesel", derive(diesel::prelude::QueryableByName))]
pub struct UserState {
    #[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Bool))]
    pub is_suspended: bool,
    #[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Bool))]
    pub require_email_verification: bool,
    #[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Bool))]
    pub require_password_change: bool,
}

impl <A: App> UserData<A> {
    /// Indicates whether there is a password associated with this user
    /// account.
    pub fn has_password(&self) -> bool {
        self.password_hash.exists()
    }
}

impl UserState {
    /// A user is "ready" if they are not suspended, and are not required to
    /// perform some action (email verification or password change) before
    /// continuing.
    pub(crate) fn require_ready<ID: Display>(self, user_id: ID) -> Result<(), Error> {
        if self.is_suspended {
            log::info!("User #{user_id} is suspended");
            Err(Error::UserIsSuspended)
        } else if self.require_email_verification {
            log::info!("User #{user_id} requires email verification");
            Err(Error::EmailNotVerified)
        } else if self.require_password_change {
            log::info!("User #{user_id} requires password change");
            Err(Error::RequirePasswordChange)
        } else {
            Ok(())
        }
    }
}

/// Registers a new user with a password they have chosen for themselves. An
/// email verification challenge is sent, and the user must complete this
/// before they can use their account.
/// 
/// Returns the registered user with their unique id.
pub async fn register_new_user<A: App>(
    app: &mut A,
    user: A::User,
    password: Secret,
) -> Result<A::User, A::Error> {
    check_password_strength(app, &password)?;
    let hash = hashing::generate_password_hash(&password)?;
    
    register(app, user, None, hash)
        .await
}

/// Registers a new user without a password. An email verification challenge is
/// sent, and the user must complete this before they can use their account.
/// After this, the user can log in by completing further email challenges.
/// 
/// Returns the registered user with their unique id.
pub async fn register_new_user_without_password<A: App>(
    app: &mut A,
    user: A::User,
) -> Result<A::User, A::Error> {
    register(app, user, None, PasswordHash::NONE)
        .await
}

/// Registers a new user with a temporary password. Instead of an email
/// verification challenge, the user is sent an email notification with the
/// temporary password. When they first login, they will be required to choose
/// a new password.
/// 
/// Returns the registered user with their unique id.
pub async fn register_new_user_with_temporary_password<A: App>(
    app: &mut A,
    user: A::User,
) -> Result<A::User, A::Error> {
    let (password, hash) = hashing::generate_password_and_hash()?;
    
    register(app, user, Some(password), hash)
        .await
}

pub async fn change_password<A: App>(
    app: &mut A,
    auth: Auth<A>,
    old_password: Option<Secret>,
    new_password: Secret,
) -> Result<(), A::Error> {
    let user = auth.user;

    // Make sure they actually changed their password. This doesn't need to be
    // done in constant-time, because both are provided by the user.
    if matches!(&old_password, Some(old) if old.0 == new_password.0) {
        return Error::PasswordsNotDifferent.as_app_err();
    }

    check_password_strength(app, &new_password)?;

    // Verify the old password.
    let data = app
        .get_user_data_by_id(user.id())
        .await
        .map_err(Into::into)?
        .ok_or(Error::UserDataQueryFailed {user_id: user.id().into()})?;
    
    // If the account is password-protected, verify the old password
    if data.password_hash.exists() {
        if let Some(old_password) = old_password {
            // Account is password-protected, and old password is provided
            hashing::verify_password(&data.password_hash, &old_password)?;
        } else {
            // Account is password-protected, but no old password is provided
            return Error::IncorrectPassword.as_app_err();
        }
    }

    // Update the password in the database.
    let new_hash = hashing::generate_password_hash(&new_password)?;
    app.update_password(&user, new_hash, false)
        .await
        .map_err(Into::into)?;

    // Notify the user that their password has been changed, in case they
    // didn't change it themselves.
    app.send_notification(&user, Notification::PasswordChanged)
        .await
        .map_err(Into::into)?;

    Ok(())
}

pub async fn request_password_reset<A: App>(app: &mut A, user: &A::User) -> Result<(), A::Error> {
    issue_challenge(app, user, Challenge::ResetPassword)
        .await
}

fn check_password_strength<A: App>(app: &mut A, password: &Secret) -> Result<(), Error> {
    if password.0.len() < app.minimum_password_length() {
        return Err(Error::PasswordTooShort);
    }
    Ok(())
}

async fn register<A: App>(
    app: &mut A,
    mut user: A::User,
    temporary_password: Option<Secret>,
    password_hash: PasswordHash,
) -> Result<A::User, A::Error> {
    // Insert the user into the database. This has to be done first to get the
    // user's new unique id, which might be needed by the app mailer.
    let user_data = UserData {
        user: user.clone(),
        password_hash,
        state: UserState {
            is_suspended: false,
            require_password_change: temporary_password.is_some(),
            require_email_verification: temporary_password.is_none(),
        },
    };
    let user_id = app.insert_user(user_data)
        .await
        .map_err(Into::into)?;

    // Update the user's id.
    user.set_id(user_id);

    // Send the notification or challenge email.
    let result = match temporary_password {
        Some(temporary_password) => {
            let notification = Notification::UserRegistered {temporary_password};
            app.send_notification(&user, notification)
                .await
                .map_err(Into::into)
        },
        None => {
            issue_challenge(app, &user, Challenge::VerifyNewUser)
                .await
                .map_err(Into::into)
        }
    };

    if let Err(e) = result {
        // If sending the email fails, the challenge code or temporary password
        // are lost, and the user will never be able to log in.
        app.delete_user(user_id)
            .await
            .map_err(Into::into)?;

        return Err(e);
    }

    Ok(user)
}
