//! Lightweight SQLite binding, parameter, and query helpers for Durable Object storage.

use std::ops::Deref;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use storage::MAX_SAFE_INTEGER;
use worker::{Error, Result, SqlCursor, SqlStorage, SqlStorageValue};

/// A BLOB column wrapper that deserializes via `serde_bytes`, removing per-field
/// `#[serde(with = "serde_bytes")]` attributes across SQLite row types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct Blob(#[serde(with = "serde_bytes")] pub(super) Vec<u8>);

impl Blob {
    pub(super) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Blob> for Vec<u8> {
    fn from(blob: Blob) -> Self {
        blob.0
    }
}

impl Deref for Blob {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Bind an integer, rejecting any value above [`MAX_SAFE_INTEGER`] (`2^53 - 1`) instead of
/// silently clamping it.
pub(super) fn checked_integer(value: u64) -> Result<SqlStorageValue> {
    if value > MAX_SAFE_INTEGER {
        return Err(Error::RustError("integer exceeds MAX_SAFE_INTEGER".into()));
    }
    Ok(SqlStorageValue::Integer(value as i64))
}

/// Converts a Rust parameter into a checked [`SqlStorageValue`].
pub(super) trait ToSql {
    fn to_sql(self) -> Result<SqlStorageValue>;
}

impl ToSql for &[u8] {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::Blob(self.to_vec()))
    }
}

impl ToSql for &Vec<u8> {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::Blob(self.clone()))
    }
}

impl ToSql for Vec<u8> {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::Blob(self))
    }
}

impl ToSql for &str {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::String(self.to_owned()))
    }
}

impl ToSql for &String {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::String(self.clone()))
    }
}

impl ToSql for String {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::String(self))
    }
}

impl ToSql for u64 {
    fn to_sql(self) -> Result<SqlStorageValue> {
        checked_integer(self)
    }
}

impl ToSql for u32 {
    fn to_sql(self) -> Result<SqlStorageValue> {
        checked_integer(u64::from(self))
    }
}

impl ToSql for u8 {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::Integer(i64::from(self)))
    }
}

impl ToSql for bool {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(SqlStorageValue::Integer(i64::from(self)))
    }
}

impl ToSql for SqlStorageValue {
    fn to_sql(self) -> Result<SqlStorageValue> {
        Ok(self)
    }
}

impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(self) -> Result<SqlStorageValue> {
        match self {
            Some(value) => value.to_sql(),
            None => Ok(SqlStorageValue::Null),
        }
    }
}

/// Builds a `Result<Vec<SqlStorageValue>>` from heterogeneous [`ToSql`] expressions.
macro_rules! params {
    () => {
        Ok::<Vec<worker::SqlStorageValue>, worker::Error>(Vec::new())
    };
    ($($value:expr),+ $(,)?) => {
        (|| -> worker::Result<Vec<worker::SqlStorageValue>> {
            Ok(vec![$($crate::objects::sql::ToSql::to_sql($value)?),+])
        })()
    };
}
pub(super) use params;

pub(super) fn exec(
    sql: &SqlStorage,
    statement: &str,
    bindings: Vec<SqlStorageValue>,
) -> Result<SqlCursor> {
    let bindings = (!bindings.is_empty()).then_some(bindings);
    sql.exec(statement, bindings)
}

pub(super) fn query<T: DeserializeOwned>(
    sql: &SqlStorage,
    statement: &str,
    bindings: Vec<SqlStorageValue>,
) -> Result<Vec<T>> {
    exec(sql, statement, bindings)?.to_array()
}

pub(super) fn query_one<T: DeserializeOwned>(
    sql: &SqlStorage,
    statement: &str,
    bindings: Vec<SqlStorageValue>,
) -> Result<T> {
    exec(sql, statement, bindings)?.one()
}

pub(super) fn query_opt<T: DeserializeOwned>(
    sql: &SqlStorage,
    statement: &str,
    bindings: Vec<SqlStorageValue>,
) -> Result<Option<T>> {
    Ok(query::<T>(sql, statement, bindings)?.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_newtype_round_trips_and_handles_options() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct Sample {
            required: Blob,
            present: Option<Blob>,
            absent: Option<Blob>,
        }
        let sample = Sample {
            required: Blob(vec![0, 1, 2, 255]),
            present: Some(Blob(vec![0xaa, 0xbb])),
            absent: None,
        };
        let encoded = postcard::to_allocvec(&sample).unwrap();
        let decoded: Sample = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, sample);
        assert_eq!(&*decoded.required, &[0, 1, 2, 255]);
        assert_eq!(decoded.required.into_vec(), vec![0, 1, 2, 255]);
    }

    #[test]
    fn to_sql_checks_safe_integer_bounds_and_binds_options() {
        assert_eq!(42u64.to_sql().unwrap(), SqlStorageValue::Integer(42));
        assert_eq!(
            MAX_SAFE_INTEGER.to_sql().unwrap(),
            SqlStorageValue::Integer(MAX_SAFE_INTEGER as i64)
        );
        assert!((MAX_SAFE_INTEGER + 1).to_sql().is_err());
        assert_eq!(true.to_sql().unwrap(), SqlStorageValue::Integer(1));
        assert_eq!(false.to_sql().unwrap(), SqlStorageValue::Integer(0));
        assert_eq!(None::<&[u8]>.to_sql().unwrap(), SqlStorageValue::Null);
        assert_eq!(
            Some([1u8, 2].as_slice()).to_sql().unwrap(),
            SqlStorageValue::Blob(vec![1, 2])
        );
    }
}
