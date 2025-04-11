use crate::{HashedPassword, SessionFields, SessionId, User};

macro_rules! future {
    (Output = Result<$type:ty, Error>) => {
        impl Future<Output = Result<$type, Self::Error>> + Send
    }
}

/// The interface for a backend.
pub trait Backend: Send + Sized {
    /// The user type.
    type User: User;
    /// The implementation-defined session data type.
    type SessionData: Send;
    /// The backend error type.
    type Error: std::error::Error + Send;

    /// Load the session data.
    fn load_session_data(
        &self,
        id: &SessionId,
    ) -> future!(Output = Result<Option<SessionFields<Self>>, Error>);

    /// Create a new instance of session data.
    ///
    /// This is called when a user does not have an existing session,
    /// ie. when they visit the site for the first time.
    fn create_session_data(
        &self,
    ) -> future!(Output = Result<Self::SessionData, Error>);

    /// Update the session data.
    ///
    /// This is called when the data associated with a session has changed.
    fn update_session_data(
        &self,
        id: &SessionId,
        user_id: Option<&<Self::User as User>::Id>,
        data: &Self::SessionData,
    ) -> future!(Output = Result<(), Error>);

    /// Load a user by their id.
    fn load_user(
        &self,
        id: &<Self::User as User>::Id,
    ) -> future!(Output = Result<Option<Self::User>, Error>);

    /// Load a user by their email address.
    fn load_user_by_email(
        &self,
        email: &str,
    ) -> future!(Output = Result<Option<Self::User>, Error>);

    /// Update the user password.
    fn update_user_password(
        &self,
        id: &<Self::User as User>::Id,
        hashed_password: &HashedPassword,
    ) -> future!(Output = Result<(), Error>);
}

/// The interface for a backend that stores the session id in a cookie.
pub trait CookieSessionBackend: Backend {
    /// Get the name of the session cookie.
    fn session_cookie_name(&self) -> &str {
        "sessionid"
    }
}
