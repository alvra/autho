use std::cell::Cell;

use crate::user::SessionUser;
use crate::{Authenticated, Backend, User, ValidPassword};

/// A unique identifier to associate a user with a session.
///
/// This value is intended to be shared with users to identify themselves.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "postgres",
    derive(postgres_types::ToSql, postgres_types::FromSql)
)]
pub struct SessionId(pub uuid::Uuid);

impl SessionId {
    /// Generate a new unique session id.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl std::str::FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}

/// The fields associated with session as stored by the backend.
#[derive(Debug)]
pub struct SessionFields<B: Backend> {
    /// The user id associated with the session.
    pub user_id: Option<<B::User as User>::Id>,
    /// Any implementation-defined data associated with the session.
    pub data: B::SessionData,
}

/// A user session.
pub struct Session<B: Backend> {
    /// The backend associated with the session.
    pub backend: B,
    /// Any implementation-defined data associated with the session.
    pub data: B::SessionData,
    /// The unique identifier for the session.
    id: SessionId,
    /// The (optional) user associated with the session.
    pub(crate) user: SessionUser<B::User>,
    /// Whether the session needs to be saved in the backend because it contains changes.
    needs_save: Cell<bool>,
}

impl<B: Backend> Session<B> {
    /// Create a new session.
    pub fn new(
        backend: B,
        id: SessionId,
        user_id: Option<<B::User as User>::Id>,
        data: B::SessionData,
    ) -> Self {
        Self {
            backend,
            id,
            data,
            user: SessionUser::new(user_id),
            needs_save: Cell::new(false),
        }
    }

    /// Whether the session is authenticated;
    /// ie. if there is a user logged into this session.
    pub fn is_authenticated(&self) -> bool {
        self.user.is_authenticated()
    }

    /// Get the (optional) user logged into the session.
    pub async fn user(&self) -> Result<Option<&B::User>, B::Error> {
        self.user.user(&self.backend).await
    }

    /// Get the (optional) user logged into the session.
    pub async fn user_mut(&mut self) -> Result<Option<&mut B::User>, B::Error> {
        self.user.user_mut(&self.backend).await
    }

    /// Change the user associated with the session.
    pub(crate) fn set_user_id(
        &mut self,
        user_id: Option<<B::User as User>::Id>,
    ) {
        if user_id.as_ref() != self.user.id() {
            self.needs_save();
        }
        self.user.set_id(user_id);
    }

    /// Change the user associated with the session.
    pub(crate) fn set_user(&mut self, user: Option<B::User>) {
        if user.as_ref().map(|user| user.id()) != self.user.id() {
            self.needs_save();
        }
        self.user.set_user(user);
    }

    /// Mark this session as needing to be saved in the backend.
    pub fn needs_save(&self) {
        self.needs_save.set(true);
    }

    /// Save this session in the backend, if it has been marked as needing to be saved.
    pub async fn save(&self) -> Result<(), B::Error> {
        if self.needs_save.get() {
            self.force_save().await?;
        }
        Ok(())
    }

    /// Save this session in the backend, even if it has not been marked as needing to be saved.
    pub async fn force_save(&self) -> Result<(), B::Error> {
        self.backend
            .update_session_data(&self.id, self.user.id(), &self.data)
            .await?;
        self.needs_save.set(false);
        Ok(())
    }

    /// Force a different user to be logged into the session.
    pub async fn force_login(
        &mut self,
        user_id: <B::User as User>::Id,
    ) -> Result<(), B::Error> {
        self.set_user_id(Some(user_id));
        Ok(())
    }

    /// Force a different user to be logged into the session.
    pub async fn force_login_user(
        &mut self,
        user: B::User,
    ) -> Result<(), B::Error> {
        self.set_user(Some(user));
        Ok(())
    }

    /// Try to log a user into session by password.
    ///
    /// If a user is currently logged into this session,
    /// this function tries to login the new user.
    /// If successful, the existing user is logged out.
    /// On failure, the existing user remains logged in.
    pub async fn login_by_password(
        &mut self,
        email: &str,
        password: &str,
    ) -> Result<Option<Authenticated>, B::Error> {
        crate::func::login_by_password(self, email, password).await
    }

    /// Logout the user of the session.
    ///
    /// If no user is currently logged into this session,
    /// this function does nothing.
    pub async fn logout(&mut self) -> Result<(), B::Error> {
        self.set_user(None);
        Ok(())
    }

    /// Update the password of the user logged into the session.
    ///
    /// If no user is currently logged into this session,
    /// this function does nothing.
    pub async fn update_user_password(
        &mut self,
        password: &ValidPassword,
    ) -> Result<(), B::Error> {
        crate::func::update_user_password(self, password).await
    }
}
