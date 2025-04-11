use std::error::Error;

use bytes::BytesMut;
use postgres_types::{FromSql, IsNull, ToSql, Type};

use crate::HashedPassword;

impl ToSql for HashedPassword {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>>
    where
        Self: Sized,
    {
        <&str as ToSql>::to_sql(&self.as_str(), ty, out)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        <&str as ToSql>::to_sql_checked(&self.as_str(), ty, out)
    }

    fn accepts(ty: &Type) -> bool
    where
        Self: Sized,
    {
        <&str as ToSql>::accepts(ty)
    }
}

impl<'a> FromSql<'a> for HashedPassword {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn Error + Sync + Send>> {
        let s = <String as FromSql>::from_sql(ty, raw)?;
        s.parse()
            .map_err(|e| Box::new(e) as Box<dyn Error + Sync + Send>)
    }

    fn accepts(ty: &Type) -> bool {
        <String as FromSql>::accepts(ty)
    }
}
