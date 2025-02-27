use actix_web::{
    body::MessageBody,
    cookie::{time::Duration, Cookie, SameSite},
    dev::{ServiceRequest, ServiceResponse},
    http::header::{HeaderName, HeaderValue},
    middleware::Next,
    Error,
};

use crate::{
    app::App,
    maybe_auth::MaybeAuth,
    sessions::authenticate_by_session_token,
    token_actions::AuthTokenAction,
    users::UserID, AppTypes,
};

pub async fn middleware<A: App>(
    mut request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error>
    where A: actix_web::FromRequest<Error = <A as AppTypes>::Error>,
{
    let mut app = request.extract::<A>()
        .await?;

    // Authenticate by the cookie, if there is one
    let auth = authenticate_by_session_token(&mut app, &request)
        .await?;

    match &auth {
        MaybeAuth::Authenticated(auth) => {
            log::debug!("Authenticated as user #{}, session #{}", auth.user.id(), auth.session_id);
        }
        MaybeAuth::Unauthenticated => {
            log::debug!("Not authenticated");
        }
    }

    // Make the authentication state available to the application
    auth.insert_into_request(&request);

    // Call the wrapped handler
    let mut response = next.call(request)
        .await?;

    // Tell the client not to cache the session token.
    // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching
    response.headers_mut().append(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-cache=\"Set-Cookie, Set-Cookie2\""),
    );

    // Issue or revoke the cookie, if necessary. If an action is inserted into
    // the request object, perform that action; otherwise perform the action
    // indicated by the earlier call to `authenticate_by_session_token`.
    let cookie_name = A::session_token_cookie_name(&app);

    match AuthTokenAction::take_from_request(response.request()) {
        AuthTokenAction::Issue(token) => {
            log::debug!("Issuing session cookie");

            // Issue a cookie with the appropriate attributes
            // https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies
            let mut cookie = Cookie::new(cookie_name, &token.0);

            // HTTP-only cookies are not visible to client-side JavaScript.
            cookie.set_http_only(true);

            // Only send this cookie over HTTPS connections.
            cookie.set_secure(true);

            cookie.set_same_site(if A::session_token_cookie_same_site_strict(&app) {
                // The client should only send this cookie when making requests
                // from the same site.
                SameSite::Strict
            } else {
                // The client should only send this cookie when making requests
                // from the same site, or when making safe requests from other
                // sites (e.g. GET requests by following links).
                SameSite::Lax
            });

            // TODO: Domain and Path options

            let duration = Duration::hours(A::session_expire_after_hours(&app) as i64);
            cookie.set_max_age(duration);

            response.response_mut()
                .add_cookie(&cookie)?;
        }
        AuthTokenAction::Revoke => {
            log::debug!("Revoking session cookie");

            // Revoke cookie by setting new empty cookie of the same name.
            let cookie = Cookie::new(cookie_name, "");
            response.response_mut()
                .add_removal_cookie(&cookie)?;
        }
        AuthTokenAction::DoNothing => {}
    }

    Ok(response)
}
