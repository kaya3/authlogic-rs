use actix_web::HttpRequest;

use crate::{
    app::{App, AppTypes},
    errors::Error,
    hashing,
    secret::{PasswordHash, Secret},
    sessions,
    tokens,
    users::UserID,
};

/// A type of notification which can be sent to a user by email.
#[derive(Debug)]
pub enum Notification {
    /// A new user account has been created with a temporary password.
    UserRegistered {temporary_password: Secret},

    /// The user's password has been changed; they must be notified in case
    /// they did not change it themselves.
    PasswordChanged,
}

/// A type of challenge which can be issued to a user by email.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Challenge<A: AppTypes> {
    /// When the challenge is completed, the user is logged in.
    LogIn,

    /// When the challenge is completed, the user's password is reset to a
    /// random string, and they will be required to choose a new one.
    ResetPassword,

    /// When the challenge is completed, the user's account is verified.
    VerifyNewUser,

    /// A custom challenge defined by the application.
    Custom(A::CustomChallenge),
}

/// An empty enum type, which can be used in `AppTypes` to declare that an app
/// does not issue any custom types of email challenge.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum NoCustomChallenges {}

impl NoCustomChallenges {
    /// Asserts that a custom challenge never occurs in this application.
    pub fn never_happens(self) -> ! {
        match self {}
    }
}

#[cfg_attr(feature = "diesel", derive(diesel::prelude::QueryableByName))]
pub struct ChallengeData<A: AppTypes> {
    #[diesel(embed)]
    pub user: A::User,
    
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub challenge: String,
    
    #[diesel(deserialize_as = String)]
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub code_hash: Secret,
    
    #[diesel(sql_type = diesel::sql_types::Timestamp)]
    pub expires: A::DateTime,
}

pub async fn issue_login_challenge<A: App>(
    app: &mut A,
    user: &A::User,
) -> Result<(), A::Error> {
    issue_challenge(app, user, Challenge::LogIn)
        .await
}

pub async fn issue_custom_challenge<A: App>(
    app: &mut A,
    user: &A::User,
    challenge: A::CustomChallenge,
) -> Result<(), A::Error> {
    issue_challenge(app, user, Challenge::Custom(challenge))
        .await
}

pub(crate) async fn issue_challenge<A: App>(
    app: &mut A,
    user: &A::User,
    challenge: Challenge<A>,
) -> Result<(), A::Error> {
    let (code, code_hash) = hashing::generate_challenge_code_and_hash();

    let expires_secs = 3600 * app.challenge_expire_after_hours() as u64;
    let expires = app.time_now() + std::time::Duration::from_secs(expires_secs);

    let challenge_str = to_json(&challenge)?;
    let challenge_id = app
        .insert_challenge(user, &challenge_str, code_hash, expires)
        .await
        .map_err(Into::into)?;
    let code = tokens::pack(challenge_id, code);
    
    // Send challenge email
    if let Err(e) = app.send_challenge(user, challenge, code)
        .await
    {
        // Failed to send the challenge link by email. The challenge code is now
        // unusable, since the link will not be received; delete it.
        app.delete_challenge_by_id(challenge_id)
            .await
            .map_err(Into::into)?;

        return Err(e.into());
    }

    Ok(())
}

pub async fn complete_challenge<A: App>(
    app: &mut A,
    code: Secret,
    request: &HttpRequest,
) -> Result<(A::User, Challenge<A>), A::Error> {
    let (challenge_id, challenge_code) = tokens::unpack(code)
        .ok_or(Error::IncorrectChallengeCode)?;

    let data = app
        .get_challenge_by_id(challenge_id)
        .await
        .map_err(Into::into)?
        .ok_or(Error::IncorrectChallengeCode)?;

    if app.time_now() >= data.expires {
        log::debug!("Challenge #{} has expired; deleting", challenge_id);
        app.delete_challenge_by_id(challenge_id)
            .await
            .map_err(Into::into)?;

        return Error::IncorrectChallengeCode.as_app_err();
    }

    let challenge = parse_json::<A>(data.challenge)?;

    // Check that the submitted code is correct.
    if !hashing::check_fast_hash(&challenge_code, &data.code_hash) {
        log::info!("Invalid code for challenge #{}", challenge_id);
        return Error::IncorrectChallengeCode.as_app_err();
    }

    let user = data.user;

    match challenge {
        Challenge::ResetPassword => {
            log::info!("Successful password reset challenge");
            
            // Update the database to disable password authentication for this
            // user, and require them to later change it.
            app.update_password(&user, PasswordHash::NONE, true)
                .await
                .map_err(Into::into)?;
        },
        Challenge::VerifyNewUser {..} => {
            log::info!("Successful email verification challenge");
            app.verify_user(&user)
                .await
                .map_err(Into::into)?;
        },
        Challenge::LogIn => {
            // All successful challenges result in an authenticated session;
            // don't need to do anything here.
            log::info!("Successful email login challenge for user #{}", user.id());
        },
        Challenge::Custom {..} => {
            log::info!("Successful custom challenge");
        },
    };

    // Do this after verifying, so that the user is verified before we start a
    // session for them.
    sessions::on_successful_challenge(app, &user, request)
        .await?;

    // Do this last. If anything before this returns an error, we want the
    // challenge to still exist in the database so the user can try again.
    app.delete_challenge_by_id(challenge_id)
        .await
        .map_err(Into::into)?;

    Ok((user, challenge))
}

fn parse_json<A: App>(value: impl AsRef<str>) -> Result<Challenge<A>, Error> {
    serde_json::from_str(value.as_ref())
        .map_err(Error::Serde)
}

fn to_json<A: App>(challenge: &Challenge<A>) -> Result<String, Error> {
    serde_json::to_string(challenge)
        .map_err(Error::Serde)
}
