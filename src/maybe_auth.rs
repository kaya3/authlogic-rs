use std::convert::Infallible;

use actix_web::{
    dev::Payload,
    FromRequest,
    HttpMessage,
    HttpRequest,
};

use crate::{
    app::App,
    errors::Error,
};

/// Represents an authenticated user.
#[derive(Clone)]
pub struct Auth<A: App> {
    pub user: A::User,
    pub session_id: A::ID,

    /// Forbid construction of this struct outside of this crate, to ensure
    /// correct usage.
    pub(crate) _deny_public_constructor: (),
}

/// Represents either an authenticated user, or that the current user is not
/// authenticated. Equivalent to `Option<Auth>`, but Rust doesn't allow
/// implementing third-party traits like `actix_web::FromRequest` for built-in
/// types like `Option`.
#[derive(Clone)]
pub enum MaybeAuth<A: App> {
    Authenticated(Auth<A>),
    Unauthenticated,
}

impl<A: App> MaybeAuth<A> {
    pub fn require(self) -> Result<Auth<A>, A::Error> {
        match self {
            Self::Authenticated(auth) => Ok(auth),
            Self::Unauthenticated => Error::NotAuthenticated.as_app_err(),
        }
    }

    /// Gets the authenticated user, if there is one.
    pub fn user(self) -> Option<A::User> {
        match self {
            Self::Authenticated(auth) => Some(auth.user),
            Self::Unauthenticated => None,
        }
    }

    /// Registers this authentication state with the request, so that route
    /// handlers can get the current authentication state. This should only
    /// be called by the authentication middleware.
    pub(crate) fn insert_into_request(self, request: &impl HttpMessage) {
        if let Self::Authenticated(auth) = self {
            request.extensions_mut().insert(auth);
        }
    }
}

/// Gets the authentication state for the request. This can be called from
/// route handlers, or `actix_web::FromRequest` implementations.
pub fn maybe_auth_from_request<A: App>(request: &impl HttpMessage) -> MaybeAuth<A> {
    let exts = request.extensions();
    let auth = exts.get::<Auth<A>>();
    
    match auth {
        Some(auth) => MaybeAuth::Authenticated(Auth {
            user: auth.user.clone(),
            session_id: auth.session_id,
            _deny_public_constructor: (),
        }),
        None => MaybeAuth::Unauthenticated,
    }
}

/// Gets the authenticated state for the request, or returns an error if
/// the request is not authenticated. This can be called from route
/// handlers, or `actix_web::FromRequest` implementations.
pub fn require_auth_from_request<A: App>(request: &impl HttpMessage) -> Result<Auth<A>, A::Error> {
    maybe_auth_from_request::<A>(request)
        .require()
}

/// Gets the authenticated user for the request, or returns an error if the
/// request is not authenticated. This can be called from route handlers,
/// or `actix_web::FromRequest` implementations.
pub fn require_user_from_request<A: App>(request: &impl HttpMessage) -> Result<A::User, A::Error> {
    require_auth_from_request::<A>(request)
        .map(|auth| auth.user)
}

impl<A: App> From<MaybeAuth<A>> for Option<Auth<A>> {
    fn from(value: MaybeAuth<A>) -> Self {
        match value {
            MaybeAuth::Authenticated(auth) => Some(auth),
            MaybeAuth::Unauthenticated => None,
        }
    }
}

impl<A: App> FromRequest for MaybeAuth<A> {
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self, Infallible>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let auth = maybe_auth_from_request(request);
        std::future::ready(Ok(auth))
    }
}

impl<A: App> FromRequest for Auth<A> {
    type Error = A::Error;
    type Future = std::future::Ready<Result<Self, A::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let result = require_auth_from_request(request);
        std::future::ready(result)
    }
}
