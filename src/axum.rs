use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;

use crate::{Backend, CookieSessionBackend, Session, SessionId};

pub fn get_session_id(
    cookie_name: &str,
    parts: &mut Parts,
) -> Option<SessionId> {
    let cookies = CookieJar::from_headers(&parts.headers);
    cookies.get(cookie_name)?.value().parse().ok()
}

pub async fn load_session<B: Backend + CookieSessionBackend>(
    backend: B,
    parts: &mut Parts,
) -> Result<Result<Session<B>, B>, B::Error> {
    if let Some(session_id) =
        get_session_id(backend.session_cookie_name(), parts)
    {
        if let Some(fields) = backend.load_session_data(&session_id).await? {
            Ok(Ok(Session::new(
                backend,
                session_id,
                fields.user_id,
                fields.data,
            )))
        } else {
            // NOTE: We renew the session id to ensure
            // users cannot choose their own session id.
            Ok(Err(backend))
        }
    } else {
        Ok(Err(backend))
    }
}

impl<B, S> FromRequestParts<S> for Session<B>
where
    B: CookieSessionBackend,
    B: FromRef<S>,
    B::Error: IntoResponse,
    S: Sync,
{
    type Rejection = B::Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let backend: B = FromRef::from_ref(state);
        match load_session(backend, parts).await? {
            Ok(session) => {
                // This user has an existing session,
                Ok(session)
            }
            Err(backend) => {
                // Session id not set or session does not exist (anymore).
                let session_id = SessionId::new();
                let user_id = None;
                let data = backend.create_session_data().await?;
                Ok(Session::new(backend, session_id, user_id, data))
            }
        }
    }
}
