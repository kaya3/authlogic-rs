use actix_web::HttpMessage;

use crate::secret::Secret;

/// Represents an action to be taken to update the client's cookie, if any.
/// This action should be applied to the response before it is sent.
pub(crate) enum AuthTokenAction {
    Issue(Secret),
    Revoke,
    DoNothing,
}

impl AuthTokenAction {
    /// Inserts this action into the request, so that it will be performed when
    /// the response is sent.
    pub(crate) fn insert_into_request(self, request: &impl HttpMessage) {
        request
            .extensions_mut()
            .insert(self);
    }

    /// Takes the action from the request. This should only be called once, by
    /// the authentication middleware when it is ready to perform the action
    /// by inserting the appropriate headers into the response.
    pub(crate) fn take_from_request(request: &impl HttpMessage) -> Self {
        request
            .extensions_mut()
            .remove()
            .unwrap_or(AuthTokenAction::DoNothing)
    }
}
