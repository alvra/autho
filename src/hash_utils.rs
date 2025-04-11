use password_hash::{PasswordHasher, ParamsString, Error};

/// This struct exists because a reference to a struct
/// does not implement `PasswordHasher`. Since we cannot
/// implement this foreign trait for a reference (a foreign type),
/// we instead implement it for this wrapper struct.
#[derive(Debug)]
pub struct HasherRef<T: 'static>(pub &'static T);

impl<T: 'static> Copy for HasherRef<T> {}
impl<T: 'static> Clone for HasherRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: PasswordHasher + 'static> PasswordHasher for HasherRef<T> {
    type Params = Params;

    fn hash_password_customized<'a>(
        &self,
        _password: &[u8],
        _algorithm: Option<password_hash::Ident<'a>>,
        _version: Option<password_hash::Decimal>,
        _params: Params,
        _salt: impl Into<password_hash::Salt<'a>>,
    ) -> password_hash::Result<password_hash::PasswordHash<'a>> {
        unreachable!()
    }

    fn hash_password<'a>(&self, password: &[u8], salt: impl Into<password_hash::Salt<'a>>) -> password_hash::Result<password_hash::PasswordHash<'a>> {
        <T as PasswordHasher>::hash_password(self.0, password, salt)
    }
}

/// Dummy params for the impl of [`PasswordHasher`] for [`HasherRef`].
#[derive(Clone, Default, Debug)]
pub struct Params;

impl TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(_: Params) -> Result<Self, Error> {
        unreachable!()
    }
}

impl<'a> TryFrom<&'a password_hash::PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(_: &'a password_hash::PasswordHash) -> Result<Self, password_hash::Error> {
        unreachable!()
    }
}
