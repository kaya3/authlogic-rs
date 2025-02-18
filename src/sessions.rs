use std::time::Duration;

use actix_web::{
    dev::ServiceRequest,
    HttpRequest,
};

use crate::{
    app::{App, AppTypes},
    errors::Error,
    hashing,
    maybe_auth::{Auth, MaybeAuth, maybe_auth_from_request},
    secret::Secret,
    token_actions::AuthTokenAction,
    tokens,
    users::{UserID, UserState},
};

pub struct SessionData<A: AppTypes> {
    pub user: A::User,
    pub user_state: UserState,
    pub token_hash: Secret,
    pub expires: A::DateTime,
}

pub async fn login<A: App>(
    app: &A,
    user_identifier: &str,
    password: Secret,
    request: &HttpRequest,
) -> Result<A::User, A::Error> {
    let Some(user_data) = app
        .get_user_data_by_identifier(user_identifier)
        .await?
    else {
        return Error::NoSuchUser.as_app_err();
    };

    // Check password first, to avoid leaking information about user status.
    // This also returns `Error::UserHasNoPassword` if the hash is missing.
    hashing::verify_password(&user_data.password_hash, &password)?;

    let session_token = begin_session_for_user(app, &user_data.user)
        .await?;
    AuthTokenAction::Issue(session_token)
        .insert_into_request(request);

    let user_id = user_data.user.id();
    log::debug!("Successful password login for user #{user_id}");
    
    // Check if the user is suspended, needs to verify their email, or needs to
    // change their password. Do this after creating a session, so the user can
    // use the session to change their password, and can be shown personalised
    // messages about the status of their account.
    user_data.state.require_ready(user_id)?;
    
    Ok(user_data.user)
}

impl<A: App> MaybeAuth<A> {
    pub async fn logout(self, app: &A, request: &HttpRequest) -> Result<(), A::Error> {
        if let MaybeAuth::Authenticated(auth) = self {
            auth.logout(app, request)
                .await?;
        }

        Ok(())
    }
}

impl<A: App> Auth<A> {
    pub async fn logout(self, app: &A, request: &HttpRequest) -> Result<(), A::Error> {
        log::debug!("Logging out user #{}", self.user.id());

        app.delete_session_by_id(self.session_id)
            .await?;
        AuthTokenAction::Revoke
            .insert_into_request(request);

        Ok(())
    }
}

/// Begins a new session for the user who completed the challenge, or renews an
/// existing session if the user is already logged in.
pub(crate) async fn on_successful_challenge<A: App>(
    app: &A,
    user: &A::User,
    request: &HttpRequest,
) -> Result<(), A::Error> {
    let maybe_auth = maybe_auth_from_request::<A>(request);

    let new_session_token = match maybe_auth {
        MaybeAuth::Authenticated(auth) if auth.user.id() == user.id() => {
            // The user already has a valid session token, but completing a
            // challenge often means the user is about to get a new privilege.
            // It is more secure to create a new session token, than to change
            // the privilege level granted by the old session token.
            //
            // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change
            renew_by_id(app, auth.session_id)
                .await?
        }
        _ => {
            begin_session_for_user(app, user)
                .await?
        },
    };

    AuthTokenAction::Issue(new_session_token)
        .insert_into_request(request);

    Ok(())
}

/// Determines the authentication state from the user's session token, and
/// a needed action (if any) to update the client's cookie in case their
/// token is renewed, or the token is expired or otherwise invalid.
pub(crate) async fn authenticate_by_session_token<A: App>(
    app: &A,
    request: &ServiceRequest,
) -> Result<MaybeAuth<A>, A::Error> {
    let revoke_cookie = || {
        AuthTokenAction::Revoke
            .insert_into_request(request);
        Ok(MaybeAuth::Unauthenticated)
    };

    let Some(cookie) = request.cookie(app.session_token_cookie_name()) else {
        // The user has no session cookie.
        log::debug!("Request has no session cookie");
        return Ok(MaybeAuth::Unauthenticated);
    };

    // Sadly, the `actix_web` and `cookie` crates don't provide any API for
    // securely zeroizing cookies after use; this is the best we can easily do.
    let cookie_value = Secret(cookie.value().to_string());
    drop(cookie);

    let Some((session_id, session_token)) = tokens::unpack(cookie_value) else {
        // The user's cookie isn't in the correct format for a session token.
        log::info!("Invalid session token format");
        return revoke_cookie();
    };

    log::debug!("Request has cookie claiming session #{}", session_id);

    let Some(session) = app.get_session_by_id(session_id)
        .await?
    else {
        // The unpacked cookie refers to a session ID which doesn't exist in
        // the database. Could be an old cookie from an expired session, or an
        // attacker.
        log::debug!("No such session #{}", session_id);
        return revoke_cookie();
    };

    if session.expires <= app.time_now() {
        // The session exists in the database, but is expired - delete it.
        log::debug!("Session #{} has expired; revoking", session_id);
        app.delete_session_by_id(session_id)
            .await?;
        return revoke_cookie();
    }

    // Check the token from the cookie against the stored hash.
    if !hashing::check_fast_hash(&session_token, &session.token_hash) {
        // The unpacked token in the user's cookie doesn't match the session ID
        // it claims to belong to. Could be an old token for a session which
        // was since renewed, or an attacker.
        log::info!("Invalid session token for session #{}", session_id);

        // Revoke cookie, but don't delete session from database; an attacker
        // could give incorrect tokens for guessed session IDs.
        return revoke_cookie();
    }

    // Check if the user is inactive, needs to verify their email, or needs to
    // change their password.
    session.user_state.require_ready(session.user.id())?;

    // Renew the session if it is old enough.
    if should_renew(app, session.expires) {
        let token = renew_by_id(app, session_id)
            .await?;
        AuthTokenAction::Issue(token)
            .insert_into_request(request);
    }

    Ok(MaybeAuth::Authenticated(Auth {
        user: session.user,
        session_id,
        _deny_public_constructor: (),
    }))
}

/// Generates a new session token for the given user, and inserts the session
/// into the database.
///
/// Returns the new session token. An `AuthTokenAction` must be inserted into
/// the request in order to issue the new session token cookie.
async fn begin_session_for_user<A: App>(app: &A, user: &A::User) -> Result<Secret, A::Error> {
    let (session_token, hash) = hashing::generate_session_token_and_hash();
    let session_id = app.insert_session(user, hash, expiry_time(app))
        .await?;

    log::debug!("Beginning session #{} for user #{}", session_id, user.id());

    Ok(tokens::pack(session_id, session_token))
}

/// Renews the session with the given id, updates the session in the database,
/// and returns the new session token.
async fn renew_by_id<A: App>(app: &A, session_id: A::ID) -> Result<Secret, A::Error> {
    log::debug!("Renewing session #{}", session_id);

    let (session_token, hash) = hashing::generate_session_token_and_hash();
    app.update_session_by_id(session_id, hash, expiry_time(app))
        .await?;

    Ok(tokens::pack(session_id, session_token))
}

/// Returns the DateTime at which a new session, starting at the current time,
/// will expire.
fn expiry_time<A: App>(app: &A) -> A::DateTime {
    let duration = Duration::from_secs(3600 * app.session_expire_after_hours());
    app.time_now() + duration
}

/// Determines whether the current time is past the time at which the session
/// should be renewed.
fn should_renew<A: App>(app: &A, expires: A::DateTime) -> bool {
    let renewal_period_hours = app.session_expire_after_hours() - app.session_renew_after_hours();
    let renewal_period = Duration::from_secs(3600 * renewal_period_hours as u64);
    app.time_now() + renewal_period >= expires
}
