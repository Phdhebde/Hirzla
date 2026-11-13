//! The SQLite container (`docs/format.md` § 5): creation, connection settings and the checks
//! made before anything is read.

use std::path::Path;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

use crate::error::VaultError;

/// `application_id` of a Hirzla vault ("Hzla").
pub const APPLICATION_ID: i64 = 0x487A_6C61;

/// Normative schema (§ 5.2). The stored SQL text must match it exactly.
pub const SCHEMA: &str = "CREATE TABLE header (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  body BLOB NOT NULL,
  auth BLOB NOT NULL
) STRICT;

CREATE TABLE identity (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  box BLOB NOT NULL
) STRICT;

CREATE TABLE settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  box BLOB NOT NULL
) STRICT;

CREATE TABLE operations (
  op_id BLOB PRIMARY KEY CHECK (length(op_id) = 48),
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  author_member BLOB NOT NULL CHECK (length(author_member) = 16),
  author_device BLOB NOT NULL CHECK (length(author_device) = 16),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  server_seq INTEGER,
  status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 5),
  body BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX operations_by_author
  ON operations (locker_id, author_member, author_device, seq);

CREATE INDEX operations_by_server_seq
  ON operations (locker_id, server_seq);

CREATE TABLE locker_keys (
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  epoch BLOB NOT NULL,
  box BLOB NOT NULL,
  PRIMARY KEY (locker_id, epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE index_shards (
  locker_id BLOB PRIMARY KEY CHECK (length(locker_id) = 16),
  box BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE sync_state (
  locker_id BLOB PRIMARY KEY CHECK (length(locker_id) = 16),
  box BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE contacts (
  member_id BLOB PRIMARY KEY CHECK (length(member_id) = 16),
  box BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE attachment_chunks (
  attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
  chunk INTEGER NOT NULL CHECK (chunk >= 0),
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  box BLOB NOT NULL,
  PRIMARY KEY (attachment_id, chunk)
) STRICT, WITHOUT ROWID;
";

/// Operation statuses (§ 5.2).
pub mod status {
    /// Applied.
    pub const APPLIED: i64 = 1;
    /// Local, not yet sent.
    pub const LOCAL: i64 = 4;
    /// Pruned: body replaced by an empty blob.
    pub const PRUNED: i64 = 5;
}

fn flags(create: bool) -> OpenFlags {
    let mut f = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        f |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    f
}

/// Per-connection settings of § 5.1, then read back (§ 5.3, step 2).
fn configure(conn: &Connection) -> Result<(), VaultError> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    conn.pragma_update(None, "cell_size_check", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    let get = |name: &str| -> Result<i64, VaultError> {
        Ok(conn.pragma_query_value(None, name, |r| r.get::<_, i64>(0))?)
    };
    let ok = get("secure_delete")? == 1
        && get("trusted_schema")? == 0
        && get("cell_size_check")? == 1
        && get("temp_store")? == 2
        && conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?;
    if ok {
        Ok(())
    } else {
        Err(VaultError::Storage)
    }
}

/// Creates a new, empty container with the schema. Refuses an existing path.
///
/// # Errors
/// [`VaultError::AlreadyExists`] or [`VaultError::Storage`].
pub fn create(path: &Path) -> Result<Connection, VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let conn = Connection::open_with_flags(path, flags(true))?;
    conn.pragma_update(None, "page_size", 4096)?;
    conn.pragma_update(None, "auto_vacuum", "FULL")?;
    conn.pragma_update(None, "encoding", "UTF-8")?;
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(VaultError::Storage);
    }
    conn.pragma_update(None, "application_id", APPLICATION_ID)?;
    conn.pragma_update(None, "user_version", i64::from(crate::FORMAT_VERSION))?;
    configure(&conn)?;
    conn.execute_batch(&format!("BEGIN;\n{SCHEMA}\nCOMMIT;"))?;
    Ok(conn)
}

/// Opens an existing container and runs steps 1 to 4 of § 5.3.
///
/// # Errors
/// [`VaultError::NotAVault`], [`VaultError::UnsupportedVersion`], [`VaultError::Corrupt`] or
/// [`VaultError::Storage`].
pub fn open(path: &Path) -> Result<Connection, VaultError> {
    if !path.is_file() {
        return Err(VaultError::NotFound);
    }
    let conn = Connection::open_with_flags(path, flags(false))?;
    let get = |name: &str| -> Result<i64, VaultError> {
        conn.pragma_query_value(None, name, |r| r.get::<_, i64>(0))
            .map_err(|_| VaultError::NotAVault)
    };
    if get("application_id")? != APPLICATION_ID {
        return Err(VaultError::NotAVault);
    }
    if get("user_version")? != i64::from(crate::FORMAT_VERSION) {
        return Err(VaultError::UnsupportedVersion);
    }
    if get("page_size")? != 4096 || get("auto_vacuum")? != 1 {
        return Err(VaultError::Corrupt);
    }
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(|_| VaultError::Corrupt)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(VaultError::Corrupt);
    }
    configure(&conn)?;
    let check: String = conn
        .pragma_query_value(None, "quick_check", |r| r.get(0))
        .map_err(|_| VaultError::Corrupt)?;
    if check != "ok" {
        return Err(VaultError::Corrupt);
    }
    check_schema(&conn)?;
    Ok(conn)
}

type SchemaRow = (String, String, String, Option<String>);

fn schema_rows(conn: &Connection) -> Result<Vec<SchemaRow>, VaultError> {
    let mut stmt =
        conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn info_rows(
    conn: &Connection,
    pragma: &str,
    object: &str,
) -> Result<Vec<Vec<String>>, VaultError> {
    let sql = format!("SELECT * FROM pragma_{pragma}(?1)");
    let mut stmt = conn.prepare(&sql)?;
    let columns = stmt.column_count();
    let rows = stmt
        .query_map([object], |r| {
            (0..columns)
                .map(|i| {
                    let v: rusqlite::types::Value = r.get(i)?;
                    Ok(format!("{v:?}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Step 4 of § 5.3: same objects as the normative schema, nothing else, same columns.
fn check_schema(conn: &Connection) -> Result<(), VaultError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    let expected = schema_rows(&reference)?;
    let actual = schema_rows(conn).map_err(|_| VaultError::Corrupt)?;
    if expected != actual {
        return Err(VaultError::Corrupt);
    }
    for (kind, name, _, _) in &expected {
        let pragma = if kind == "table" {
            "table_xinfo"
        } else {
            "index_xinfo"
        };
        if info_rows(&reference, pragma, name)?
            != info_rows(conn, pragma, name).map_err(|_| VaultError::Corrupt)?
        {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}
