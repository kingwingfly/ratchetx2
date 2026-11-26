//! Lightweight SQLite binding, parameter, and query helpers for Durable Object storage.

use std::ops::Deref;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use storage::MAX_SAFE_INTEGER;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{Error, Result, SqlStorage, SqlStorageValue, State};

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

/// SQLite execution backend shared between Cloudflare Durable Object SQLite ([`WorkerSql`]) and
/// native in-memory `rusqlite` tests (`TestSql`).
///
/// Production SQL stays strictly free of SQL `BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT` keywords
/// because Cloudflare Durable Object SQLite requires transactions to run through
/// `DurableObjectStorage.transactionSync`.
pub(crate) trait SqlExec {
    fn exec(&self, statement: &str, bindings: Vec<SqlStorageValue>) -> Result<()>;

    fn exec_batch(&self, statements: &str) -> Result<()>;

    fn query<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Vec<T>>;

    fn query_one<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<T>;

    fn query_opt<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Option<T>>;

    fn transaction_sync<T>(&self, f: impl FnOnce(&Self) -> Result<T>) -> Result<T>;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = worker::worker_sys::DurableObjectStorage, js_name = DurableObjectStorage)]
    type TransactionalStorage;

    #[wasm_bindgen(method, catch, js_name = transactionSync)]
    fn storage_transaction_sync(
        this: &TransactionalStorage,
        callback: &mut dyn FnMut() -> std::result::Result<(), JsValue>,
    ) -> std::result::Result<JsValue, JsValue>;
}

/// Production [`SqlExec`] backed by Cloudflare Durable Object SQLite storage.
pub(crate) struct WorkerSql<'a>(pub(crate) &'a State, pub(crate) &'a SqlStorage);

impl SqlExec for WorkerSql<'_> {
    fn exec(&self, statement: &str, bindings: Vec<SqlStorageValue>) -> Result<()> {
        let bindings = (!bindings.is_empty()).then_some(bindings);
        self.1.exec(statement, bindings)?;
        Ok(())
    }

    fn exec_batch(&self, statements: &str) -> Result<()> {
        self.1.exec(statements, None)?;
        Ok(())
    }

    fn query<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Vec<T>> {
        let bindings = (!bindings.is_empty()).then_some(bindings);
        self.1.exec(statement, bindings)?.to_array()
    }

    fn query_one<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<T> {
        let bindings = (!bindings.is_empty()).then_some(bindings);
        self.1.exec(statement, bindings)?.one()
    }

    fn query_opt<T: DeserializeOwned>(
        &self,
        statement: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Option<T>> {
        Ok(self.query::<T>(statement, bindings)?.into_iter().next())
    }

    fn transaction_sync<T>(&self, f: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let storage = self.0.storage();
        let raw: &TransactionalStorage = storage.as_raw().unchecked_ref();
        let mut output = None;
        let mut operation = Some(f);
        let transaction = raw.storage_transaction_sync(&mut || {
            let run = operation
                .take()
                .ok_or_else(|| JsValue::from_str("transaction already ran"))?;
            let result = run(self);
            let failed = result.is_err();
            output = Some(result);
            if failed {
                // Throw across the JS boundary so SQLite rolls back every statement.
                return Err(JsValue::from_str("transaction rollback"));
            }
            Ok(())
        });
        match (transaction, output) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(_), Some(Ok(value))) => Ok(value),
            (Ok(_), None) => Err(Error::RustError("transaction callback did not run".into())),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use native_test::TestSql;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_test {
    use std::{
        cell::{Cell, RefCell},
        fmt,
    };

    use rusqlite::{
        Connection, Row, params_from_iter,
        types::{Value, ValueRef},
    };
    use serde::{
        de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor},
        forward_to_deserialize_any,
    };
    use worker::{Error, Result, SqlStorageValue};

    use super::SqlExec;

    /// In-memory bundled SQLite [`SqlExec`] for fast deterministic native tests.
    ///
    /// `SAVEPOINT` / `RELEASE` / `ROLLBACK TO` are strictly confined inside
    /// [`TestSql::transaction_sync`] so production SQL remains free of transaction keywords.
    pub(crate) struct TestSql {
        conn: RefCell<Connection>,
        savepoint_depth: Cell<u32>,
    }

    impl TestSql {
        pub(crate) fn in_memory() -> Self {
            let conn = Connection::open_in_memory().expect("open in-memory SQLite");
            Self {
                conn: RefCell::new(conn),
                savepoint_depth: Cell::new(0),
            }
        }
    }

    fn sqlite_err(error: rusqlite::Error) -> Error {
        Error::RustError(format!("sqlite error: {error}"))
    }

    fn to_rusqlite_value(value: SqlStorageValue) -> Value {
        match value {
            SqlStorageValue::Null => Value::Null,
            SqlStorageValue::Boolean(flag) => Value::Integer(i64::from(flag)),
            SqlStorageValue::Integer(int) => Value::Integer(int),
            SqlStorageValue::Float(float) => Value::Real(float),
            SqlStorageValue::String(text) => Value::Text(text),
            SqlStorageValue::Blob(bytes) => Value::Blob(bytes),
        }
    }

    impl SqlExec for TestSql {
        fn exec(&self, statement: &str, bindings: Vec<SqlStorageValue>) -> Result<()> {
            let conn = self.conn.borrow();
            let values: Vec<Value> = bindings.into_iter().map(to_rusqlite_value).collect();
            let mut stmt = conn.prepare(statement).map_err(sqlite_err)?;
            stmt.execute(params_from_iter(values)).map_err(sqlite_err)?;
            Ok(())
        }

        fn exec_batch(&self, statements: &str) -> Result<()> {
            self.conn
                .borrow()
                .execute_batch(statements)
                .map_err(sqlite_err)
        }

        fn query<T: DeserializeOwned>(
            &self,
            statement: &str,
            bindings: Vec<SqlStorageValue>,
        ) -> Result<Vec<T>> {
            let conn = self.conn.borrow();
            let values: Vec<Value> = bindings.into_iter().map(to_rusqlite_value).collect();
            let mut stmt = conn.prepare(statement).map_err(sqlite_err)?;
            let columns: Vec<String> = stmt.column_names().into_iter().map(str::to_owned).collect();
            let mut rows = stmt.query(params_from_iter(values)).map_err(sqlite_err)?;
            let mut out = Vec::new();
            while let Some(row) = rows.next().map_err(sqlite_err)? {
                let item = T::deserialize(RowDeserializer {
                    row,
                    columns: &columns,
                })
                .map_err(|e| Error::RustError(format!("row deserialize error: {e}")))?;
                out.push(item);
            }
            Ok(out)
        }

        fn query_one<T: DeserializeOwned>(
            &self,
            statement: &str,
            bindings: Vec<SqlStorageValue>,
        ) -> Result<T> {
            let mut rows = self.query::<T>(statement, bindings)?;
            match rows.len() {
                1 => Ok(rows.pop().expect("len checked")),
                0 => Err(Error::RustError("expected 1 row, got 0".into())),
                n => Err(Error::RustError(format!("expected 1 row, got {n}"))),
            }
        }

        fn query_opt<T: DeserializeOwned>(
            &self,
            statement: &str,
            bindings: Vec<SqlStorageValue>,
        ) -> Result<Option<T>> {
            Ok(self.query::<T>(statement, bindings)?.into_iter().next())
        }

        fn transaction_sync<T>(&self, f: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
            let prev_depth = self.savepoint_depth.get();
            let depth = prev_depth + 1;
            self.savepoint_depth.set(depth);
            let sp = format!("sp_{depth}");
            {
                let conn = self.conn.borrow();
                if let Err(err) = conn.execute_batch(&format!("SAVEPOINT {sp};")) {
                    self.savepoint_depth.set(prev_depth);
                    return Err(sqlite_err(err));
                }
            }

            struct SavepointGuard<'a> {
                sql: &'a TestSql,
                sp: String,
                prev_depth: u32,
                armed: bool,
            }

            impl Drop for SavepointGuard<'_> {
                fn drop(&mut self) {
                    if self.armed {
                        if let Ok(conn) = self.sql.conn.try_borrow() {
                            let _ = conn.execute_batch(&format!(
                                "ROLLBACK TO SAVEPOINT {0}; RELEASE SAVEPOINT {0};",
                                self.sp
                            ));
                        }
                        self.sql.savepoint_depth.set(self.prev_depth);
                    }
                }
            }

            let mut guard = SavepointGuard {
                sql: self,
                sp: sp.clone(),
                prev_depth,
                armed: true,
            };

            let result = f(self);
            match result {
                Ok(value) => {
                    let release = self
                        .conn
                        .borrow()
                        .execute_batch(&format!("RELEASE SAVEPOINT {sp};"));
                    match release {
                        Ok(()) => {
                            guard.armed = false;
                            self.savepoint_depth.set(prev_depth);
                            Ok(value)
                        }
                        Err(err) => Err(sqlite_err(err)),
                    }
                }
                Err(err) => {
                    let _ = self.conn.borrow().execute_batch(&format!(
                        "ROLLBACK TO SAVEPOINT {sp}; RELEASE SAVEPOINT {sp};"
                    ));
                    guard.armed = false;
                    self.savepoint_depth.set(prev_depth);
                    Err(err)
                }
            }
        }
    }

    #[derive(Debug)]
    struct DeError(String);

    impl fmt::Display for DeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for DeError {}

    impl de::Error for DeError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Self(msg.to_string())
        }
    }

    struct RowDeserializer<'row, 'cols> {
        row: &'row Row<'row>,
        columns: &'cols [String],
    }

    impl<'de> Deserializer<'de> for RowDeserializer<'_, '_> {
        type Error = DeError;

        fn deserialize_any<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            self.deserialize_map(visitor)
        }

        fn deserialize_map<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_map(RowMapAccess {
                row: self.row,
                columns: self.columns,
                index: 0,
            })
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _fields: &'static [&'static str],
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            self.deserialize_map(visitor)
        }

        forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
            option unit unit_struct newtype_struct seq tuple tuple_struct enum identifier ignored_any
        }
    }

    struct RowMapAccess<'row, 'cols> {
        row: &'row Row<'row>,
        columns: &'cols [String],
        index: usize,
    }

    impl<'de> MapAccess<'de> for RowMapAccess<'_, '_> {
        type Error = DeError;

        fn next_key_seed<K: de::DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> std::result::Result<Option<K::Value>, DeError> {
            let Some(name) = self.columns.get(self.index) else {
                return Ok(None);
            };
            seed.deserialize(KeyDeserializer(name.as_str())).map(Some)
        }

        fn next_value_seed<V: de::DeserializeSeed<'de>>(
            &mut self,
            seed: V,
        ) -> std::result::Result<V::Value, DeError> {
            let value = self
                .row
                .get_ref(self.index)
                .map_err(|e| DeError(e.to_string()))?;
            self.index += 1;
            seed.deserialize(ValueDeserializer(value))
        }
    }

    struct KeyDeserializer<'a>(&'a str);

    impl<'de> Deserializer<'de> for KeyDeserializer<'_> {
        type Error = DeError;

        fn deserialize_any<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_str(self.0)
        }

        forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
            option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum
            identifier ignored_any
        }
    }

    struct ValueDeserializer<'row>(ValueRef<'row>);

    impl ValueDeserializer<'_> {
        fn expect_integer(&self) -> std::result::Result<i64, DeError> {
            match self.0 {
                ValueRef::Integer(v) => Ok(v),
                other => Err(DeError(format!("expected integer, got {other:?}"))),
            }
        }

        fn expect_str(&self) -> std::result::Result<&str, DeError> {
            match self.0 {
                ValueRef::Text(bytes) => {
                    std::str::from_utf8(bytes).map_err(|e| DeError(format!("invalid utf-8: {e}")))
                }
                other => Err(DeError(format!("expected text, got {other:?}"))),
            }
        }

        fn expect_bytes(&self) -> std::result::Result<&[u8], DeError> {
            match self.0 {
                ValueRef::Blob(bytes) => Ok(bytes),
                other => Err(DeError(format!("expected blob, got {other:?}"))),
            }
        }
    }

    impl<'de> Deserializer<'de> for ValueDeserializer<'_> {
        type Error = DeError;

        fn deserialize_any<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            match self.0 {
                ValueRef::Null => visitor.visit_unit(),
                ValueRef::Integer(v) => visitor.visit_i64(v),
                ValueRef::Real(v) => visitor.visit_f64(v),
                ValueRef::Text(bytes) => {
                    let s = std::str::from_utf8(bytes)
                        .map_err(|e| DeError(format!("invalid utf-8: {e}")))?;
                    visitor.visit_str(s)
                }
                ValueRef::Blob(bytes) => visitor.visit_bytes(bytes),
            }
        }

        fn deserialize_bool<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_bool(self.expect_integer()? != 0)
        }

        fn deserialize_i8<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = i8::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("i8 out of range: {e}")))?;
            visitor.visit_i8(v)
        }

        fn deserialize_i16<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = i16::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("i16 out of range: {e}")))?;
            visitor.visit_i16(v)
        }

        fn deserialize_i32<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = i32::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("i32 out of range: {e}")))?;
            visitor.visit_i32(v)
        }

        fn deserialize_i64<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_i64(self.expect_integer()?)
        }

        fn deserialize_u8<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = u8::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("u8 out of range: {e}")))?;
            visitor.visit_u8(v)
        }

        fn deserialize_u16<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = u16::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("u16 out of range: {e}")))?;
            visitor.visit_u16(v)
        }

        fn deserialize_u32<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = u32::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("u32 out of range: {e}")))?;
            visitor.visit_u32(v)
        }

        fn deserialize_u64<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            let v = u64::try_from(self.expect_integer()?)
                .map_err(|e| DeError(format!("u64 out of range: {e}")))?;
            visitor.visit_u64(v)
        }

        fn deserialize_f32<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            match self.0 {
                ValueRef::Real(v) => visitor.visit_f32(v as f32),
                ValueRef::Integer(v) => visitor.visit_f32(v as f32),
                other => Err(DeError(format!("expected float, got {other:?}"))),
            }
        }

        fn deserialize_f64<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            match self.0 {
                ValueRef::Real(v) => visitor.visit_f64(v),
                ValueRef::Integer(v) => visitor.visit_f64(v as f64),
                other => Err(DeError(format!("expected float, got {other:?}"))),
            }
        }

        fn deserialize_str<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_str(self.expect_str()?)
        }

        fn deserialize_string<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_str(self.expect_str()?)
        }

        fn deserialize_bytes<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_bytes(self.expect_bytes()?)
        }

        fn deserialize_byte_buf<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_bytes(self.expect_bytes()?)
        }

        fn deserialize_option<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            match self.0 {
                ValueRef::Null => visitor.visit_none(),
                _ => visitor.visit_some(self),
            }
        }

        fn deserialize_newtype_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_newtype_struct(self)
        }

        fn deserialize_seq<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_seq(BlobSeqAccess(self.expect_bytes()?))
        }

        fn deserialize_ignored_any<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> std::result::Result<V::Value, DeError> {
            visitor.visit_unit()
        }

        forward_to_deserialize_any! {
            char unit unit_struct tuple tuple_struct map struct enum identifier
        }
    }

    struct BlobSeqAccess<'a>(&'a [u8]);

    impl<'de> SeqAccess<'de> for BlobSeqAccess<'_> {
        type Error = DeError;

        fn next_element_seed<T: de::DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> std::result::Result<Option<T::Value>, DeError> {
            let Some((&first, rest)) = self.0.split_first() else {
                return Ok(None);
            };
            self.0 = rest;
            seed.deserialize(ValueDeserializer(ValueRef::Integer(i64::from(first))))
                .map(Some)
        }
    }
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

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use super::*;

        #[test]
        fn row_deserializer_handles_blobs_options_numbers_text_floats_and_ignored_columns() {
            #[derive(Debug, PartialEq, Deserialize)]
            struct FullRow {
                id: u64,
                signed: i64,
                small: u32,
                flag: bool,
                ratio: f64,
                label: String,
                opt_text: Option<String>,
                missing_text: Option<String>,
                raw: Blob,
                opt_blob: Option<Blob>,
                missing_blob: Option<Blob>,
            }

            let sql = TestSql::in_memory();
            sql.exec_batch(
                "CREATE TABLE t (
                    id INTEGER NOT NULL,
                    signed INTEGER NOT NULL,
                    small INTEGER NOT NULL,
                    flag INTEGER NOT NULL,
                    ratio REAL NOT NULL,
                    label TEXT NOT NULL,
                    opt_text TEXT,
                    missing_text TEXT,
                    raw BLOB NOT NULL,
                    opt_blob BLOB,
                    missing_blob BLOB,
                    extra_ignored TEXT
                );",
            )
            .unwrap();
            sql.exec(
                "INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    SqlStorageValue::Integer(42),
                    SqlStorageValue::Integer(-7),
                    SqlStorageValue::Integer(9),
                    SqlStorageValue::Boolean(true),
                    SqlStorageValue::Float(3.5),
                    SqlStorageValue::String("hello".into()),
                    SqlStorageValue::String("present".into()),
                    SqlStorageValue::Null,
                    SqlStorageValue::Blob(vec![0, 1, 255]),
                    SqlStorageValue::Blob(vec![0xde, 0xad]),
                    SqlStorageValue::Null,
                    SqlStorageValue::String("ignored".into()),
                ],
            )
            .unwrap();

            let row: FullRow = sql.query_one("SELECT * FROM t", vec![]).unwrap();
            assert_eq!(
                row,
                FullRow {
                    id: 42,
                    signed: -7,
                    small: 9,
                    flag: true,
                    ratio: 3.5,
                    label: "hello".into(),
                    opt_text: Some("present".into()),
                    missing_text: None,
                    raw: Blob(vec![0, 1, 255]),
                    opt_blob: Some(Blob(vec![0xde, 0xad])),
                    missing_blob: None,
                }
            );
        }

        #[test]
        fn row_deserializer_rejects_negative_into_unsigned_and_enforces_query_one_cardinality() {
            #[derive(Debug, Deserialize)]
            struct UnsignedRow {
                #[allow(dead_code)]
                val: u64,
            }

            let sql = TestSql::in_memory();
            sql.exec_batch("CREATE TABLE nums (val INTEGER NOT NULL);")
                .unwrap();

            // 0 rows -> query_one errors, query_opt returns None.
            assert!(
                sql.query_one::<UnsignedRow>("SELECT val FROM nums", vec![])
                    .is_err()
            );
            assert!(
                sql.query_opt::<UnsignedRow>("SELECT val FROM nums", vec![])
                    .unwrap()
                    .is_none()
            );

            // Negative integer -> error when deserializing into u64.
            sql.exec(
                "INSERT INTO nums VALUES (?)",
                vec![SqlStorageValue::Integer(-1)],
            )
            .unwrap();
            assert!(
                sql.query_one::<UnsignedRow>("SELECT val FROM nums", vec![])
                    .is_err()
            );

            // >1 rows -> query_one errors.
            sql.exec("DELETE FROM nums", vec![]).unwrap();
            sql.exec("INSERT INTO nums VALUES (1), (2)", vec![])
                .unwrap();
            assert!(
                sql.query_one::<UnsignedRow>("SELECT val FROM nums", vec![])
                    .is_err()
            );
        }

        #[test]
        fn bundled_sqlite_supports_returning_json_each_json_extract_unhex_and_changes() {
            #[derive(Debug, PartialEq, Eq, Deserialize)]
            struct ReturnedRow {
                k: Blob,
                v: u64,
            }
            #[derive(Debug, Deserialize)]
            struct CountRow {
                count: u64,
            }

            let sql = TestSql::in_memory();
            sql.exec_batch("CREATE TABLE kv (k BLOB PRIMARY KEY, v INTEGER NOT NULL);")
                .unwrap();
            let inserted: ReturnedRow = sql
                .query_one(
                    "INSERT INTO kv (k, v) VALUES (?, ?) RETURNING k, v",
                    params![[0xaa_u8, 0xbb].as_slice(), 7u64].unwrap(),
                )
                .unwrap();
            assert_eq!(
                inserted,
                ReturnedRow {
                    k: Blob(vec![0xaa, 0xbb]),
                    v: 7
                }
            );

            let matched: Vec<ReturnedRow> = sql
                .query(
                    "SELECT k, v FROM kv WHERE (k, v) IN ( \
                        SELECT unhex(json_extract(value, '$[0]')), \
                               CAST(json_extract(value, '$[1]') AS INTEGER) \
                        FROM json_each(?) \
                    )",
                    params![r#"[["aabb",7]]"#].unwrap(),
                )
                .unwrap();
            assert_eq!(matched, vec![inserted]);

            sql.exec("DELETE FROM kv WHERE v = 7", vec![]).unwrap();
            let changed: CountRow = sql.query_one("SELECT changes() AS count", vec![]).unwrap();
            assert_eq!(changed.count, 1);
        }

        #[test]
        fn transaction_sync_commits_rolls_back_and_supports_nested_savepoints() {
            #[derive(Debug, Deserialize)]
            struct CountRow {
                count: u64,
            }

            let sql = TestSql::in_memory();
            sql.exec_batch("CREATE TABLE items (id INTEGER PRIMARY KEY);")
                .unwrap();

            // Commit path persists writes.
            sql.transaction_sync(|tx| tx.exec("INSERT INTO items VALUES (1)", vec![]))
                .unwrap();
            assert_eq!(
                sql.query_one::<CountRow>("SELECT count(*) AS count FROM items", vec![])
                    .unwrap()
                    .count,
                1
            );

            // Rollback path discards every statement in the failing transaction.
            let err = sql
                .transaction_sync(|tx| {
                    tx.exec("INSERT INTO items VALUES (2)", vec![])?;
                    tx.exec("INSERT INTO items VALUES (3)", vec![])?;
                    Err::<(), _>(Error::RustError("mid-tx failure".into()))
                })
                .unwrap_err();
            assert!(err.to_string().contains("mid-tx failure"));
            assert_eq!(
                sql.query_one::<CountRow>("SELECT count(*) AS count FROM items", vec![])
                    .unwrap()
                    .count,
                1
            );

            // Nested rollback leaves outer savepoint intact when handled.
            sql.transaction_sync(|outer| {
                outer.exec("INSERT INTO items VALUES (10)", vec![])?;
                let inner_err = outer.transaction_sync(|inner| {
                    inner.exec("INSERT INTO items VALUES (11)", vec![])?;
                    Err::<(), _>(Error::RustError("inner fail".into()))
                });
                assert!(inner_err.is_err());
                Ok(())
            })
            .unwrap();
            assert_eq!(
                sql.query_one::<CountRow>("SELECT count(*) AS count FROM items", vec![])
                    .unwrap()
                    .count,
                2
            );
        }
    }
}
