use tokio::sync::OnceCell;

use crate::{Backend, HashedPassword};

/// The interface for a user.
pub trait User: Send {
    /// The type used to identify a user.
    type Id: Clone + PartialEq + std::fmt::Debug + Send;

    /// Get the id of the user.
    fn id(&self) -> &Self::Id;

    /// Get the email address of the user.
    fn email(&self) -> &str;

    /// Get the hashed password of the user.
    fn hashed_password(&self) -> Option<&HashedPassword>;

    /// Update the hashed password of this user.
    ///
    /// This only needs to be implemented in projects where
    /// the password is used outside of this crate,
    /// and that need to maintain an up-to-date password.
    fn set_hashed_password(&mut self, hashed_password: Option<HashedPassword>) {
        let _ = hashed_password;
    }
}

/// The user data stored in a session.
pub struct SessionUser<U: User> {
    /// The id of the user.
    id: Option<U::Id>,
    /// The user itself.
    user: OnceCell<U>,
}

impl<U: User> SessionUser<U> {
    pub fn new(id: Option<U::Id>) -> Self {
        Self {
            id,
            user: OnceCell::new(),
        }
    }

    /// Whether the user is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.id.is_some()
    }

    pub fn id(&self) -> Option<&U::Id> {
        self.id.as_ref()
    }

    pub fn set_id(&mut self, id: Option<U::Id>) {
        if id != self.id {
            self.id = id;
            self.user = OnceCell::new();
        }
    }

    pub async fn user<B: Backend<User = U>>(
        &self,
        backend: &B,
    ) -> Result<Option<&U>, B::Error> {
        enum Error<E> {
            UserNotFound,
            Inner(E),
        }
        if let Some(id) = &self.id {
            let result = self
                .user
                .get_or_try_init(async || match backend.load_user(id).await {
                    Ok(Some(user)) => Ok(user),
                    Ok(None) => Err(Error::UserNotFound),
                    Err(e) => Err(Error::Inner(e)),
                })
                .await;
            match result {
                Ok(user) => Ok(Some(user)),
                Err(Error::UserNotFound) => Ok(None),
                Err(Error::Inner(e)) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn user_mut<B: Backend<User = U>>(
        &mut self,
        backend: &B,
    ) -> Result<Option<&mut U>, B::Error> {
        self.user(backend).await?;
        Ok(self.user.get_mut())
    }

    pub fn get_mut(&mut self) -> Option<&mut U> {
        self.user.get_mut()
    }

    pub fn set_user(&mut self, user: Option<U>) {
        self.id = user.as_ref().map(|user| user.id().clone());
        self.user = OnceCell::new_with(user);
    }
}
