use actix_web::cookie::Cookie;

use crate::{
    App,
    Auth,
    Secret,
    UserData,
    sessions::begin_session_for_user,
};

/// Creates a session for the given user, returning the session token and an
/// `Auth` struct representing an authenticated request.
/// 
/// This function must only be used during tests, as it inherently creates a
/// backdoor which bypasses authentication.
async fn create_test_session<A: App>(app: &mut A, user_id: A::ID) -> (Secret, Auth<A>)
where A::DbError: std::fmt::Debug {
    let user_data = _get_user_data(app, user_id)
        .await;
    let (session_id, session_token) = begin_session_for_user(app, &user_data.user)
        .await
        .expect(&format!("Failed to insert session for user {user_id}"));

    (session_token, Auth {
        user: user_data.user,
        user_state: user_data.state,
        session_id,
        _deny_public_constructor: (),
    })
}


pub trait WithTestAuth<A: App>
where A::DbError: std::fmt::Debug {
    /// Creates a session for the given user, and inserts an `Auth` struct for
    /// that user into this request's extension data.
    /// 
    /// This function must only be used during tests, as it inherently creates
    /// a backdoor which bypasses authentication.
    fn with_test_auth(self, app: &mut A, user_id: A::ID) -> impl std::future::Future<Output = Self>;

    /// Creates an `Auth` struct representing an authenticated request for the
    /// given user, and inserts it into this request's extension data. Note
    /// that a new session is **not** created; this can be called with the id
    /// of an existing session.
    /// 
    /// This function must only be used during tests, as it inherently creates
    /// a backdoor which bypasses authentication.
    fn with_existing_test_auth(self, app: &mut A, user_id: A::ID, session_id: A::ID) -> impl std::future::Future<Output = Self>;
}

pub trait WithTestSession<A: App>
where A::DbError: std::fmt::Debug {
    /// Creates a session for the given user, and inserts the session token
    /// cookie into this request.
    /// 
    /// This function must only be used during tests, as it inherently creates
    /// a backdoor which bypasses authentication.
    fn with_test_session(self, app: &mut A, user_id: A::ID) -> impl std::future::Future<Output = Self>;
}

impl <R: actix_web::HttpMessage, A: App> WithTestAuth<A> for R
where A::DbError: std::fmt::Debug {
    async fn with_test_auth(self, app: &mut A, user_id: A::ID) -> Self {
        let (_, auth) = create_test_session(app, user_id).await;
        auth.into_maybe_auth()
            .insert_into_request(&self);

        self
    }

    async fn with_existing_test_auth(self, app: &mut A, user_id: <A>::ID, session_id: <A>::ID) -> Self {
        let user_data = _get_user_data(app, user_id).await;
        let auth = Auth::<A> {
            user: user_data.user,
            user_state: user_data.state,
            session_id,
            _deny_public_constructor: (),
        };
        auth.into_maybe_auth()
            .insert_into_request(&self);

        self
    }
}

impl <R: WithCookie, A: App> WithTestSession<A> for R
where A::DbError: std::fmt::Debug {
    async fn with_test_session(self, app: &mut A, user_id: A::ID) -> Self {
        let (token, _) = create_test_session(app, user_id).await;
        
        self.with_cookie(Cookie::new(
            app.session_token_cookie_name(),
            token.expose(),
        ))
    }
}

trait WithCookie {
    fn with_cookie(self, cookie: Cookie) -> Self;
}

impl WithCookie for actix_web::test::TestRequest {
    fn with_cookie(self, cookie: Cookie) -> Self {
        self.cookie(cookie)
    }
}

impl WithCookie for awc::ClientRequest {
    fn with_cookie(self, cookie: Cookie) -> Self {
        self.cookie(cookie)
    }
}

async fn _get_user_data<A: App>(app: &mut A, user_id: A::ID) -> UserData<A>
where A::DbError: std::fmt::Debug {
    app.get_user_data_by_id(user_id)
        .await
        .expect(&format!("Failed to fetch data for user {user_id}"))
        .expect(&format!("No such user {user_id}"))
}
