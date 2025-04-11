use crate::{Backend, Session, User, ValidPassword, Authenticated};

pub async fn login_by_password<B: Backend>(
    session: &mut Session<B>,
    email: &str,
    password: &str,
) -> Result<Option<Authenticated>, B::Error> {
    let Some(user) = session.backend.load_user_by_email(email).await? else {
        return Ok(None)
    };
    let Some(hashed_password) = user.hashed_password() else {
        return Ok(None)
    };
    let Some(auth) = hashed_password.verify(password) else {
        return Ok(None)
    };
    session.set_user(Some(user));
    Ok(Some(auth))
}

pub async fn update_user_password<B: Backend>(
    session: &mut Session<B>,
    password: &ValidPassword,
) -> Result<(), B::Error> {
    if let Some(user_id) = session.user.id() {
        let hashed_password = super::password::HashedPassword::new(password);
        session.backend.update_user_password(user_id, &hashed_password).await?;
        session.needs_save();
        if let Some(user) = session.user.get_mut() {
            user.set_hashed_password(Some(hashed_password));
        }
        Ok(())
    } else {
        Ok(())
    }
}
