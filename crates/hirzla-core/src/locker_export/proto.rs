//! Locker export operations of the local API (`docs/api-locale.md` § 19): version 9,
//! operation codes 140 to 149, error codes 140 to 149. Same frames, same CBOR profile and
//! same strict decoding as the rest of the API (`crate::proto`).

use hirzla_vault::cbor::{self, fixed, text_max, uint, Fields, Value};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::proto::{ErrorCode, MAX_PASSWORD};

/// Version of the protocol that carries the export operations.
pub const EXPORT_VERSION: u64 = 9;
/// Operation codes reserved for the export (ADR 0077).
pub const EXPORT_OPS: std::ops::RangeInclusive<u64> = 140..=149;
/// Longest path of an export file, in bytes.
pub const MAX_PATH: usize = 4096;
/// Longest locker name, in bytes (`docs/format.md` § 7.4).
pub const MAX_LOCKER_NAME: usize = 256;

/// Export operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOp {
    /// Write an encrypted export of a locker.
    LockerExport = 140,
    /// Import an export as a new locker.
    LockerImport = 141,
}

impl ExportOp {
    /// All operations.
    pub const ALL: [ExportOp; 2] = [ExportOp::LockerExport, ExportOp::LockerImport];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ExportOp> {
        ExportOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ExportOp::LockerExport => "locker_export",
            ExportOp::LockerImport => "locker_import",
        }
    }
}

/// Error codes of the export (140 to 149). The general codes of § 7 keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 140: the export password chosen is below the floor (16 characters, 8 distinct).
    PasswordWeak,
    /// 141: wrong password for the export, or its manifest was altered.
    KeyRejected,
    /// 142: not an export file, or a malformed, altered or oversized one.
    Malformed,
    /// 143: the locker is too large to be exported.
    TooLarge,
    /// 144: a file already exists at the export path.
    FileExists,
    /// 145: an export of a later version of the format.
    Unsupported,
}

impl ExportCode {
    const OWN: [ExportCode; 6] = [
        ExportCode::PasswordWeak,
        ExportCode::KeyRejected,
        ExportCode::Malformed,
        ExportCode::TooLarge,
        ExportCode::FileExists,
        ExportCode::Unsupported,
    ];

    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            ExportCode::General(c) => c as u64,
            ExportCode::PasswordWeak => 140,
            ExportCode::KeyRejected => 141,
            ExportCode::Malformed => 142,
            ExportCode::TooLarge => 143,
            ExportCode::FileExists => 144,
            ExportCode::Unsupported => 145,
        }
    }

    /// The code from its status number.
    #[must_use]
    pub fn from_status(n: u64) -> Option<ExportCode> {
        ExportCode::OWN
            .into_iter()
            .find(|c| c.status() == n)
            .or_else(|| ErrorCode::from_u64(n).map(ExportCode::General))
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ExportCode::General(c) => c.name(),
            ExportCode::PasswordWeak => "export_password_weak",
            ExportCode::KeyRejected => "export_key_rejected",
            ExportCode::Malformed => "export_malformed",
            ExportCode::TooLarge => "export_too_large",
            ExportCode::FileExists => "export_file_exists",
            ExportCode::Unsupported => "export_unsupported",
        }
    }
}

impl From<ErrorCode> for ExportCode {
    fn from(c: ErrorCode) -> Self {
        ExportCode::General(c)
    }
}

/// What an export wrote, in counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// Secrets exported.
    pub secrets: u64,
    /// Secrets in the trash, not exported.
    pub trashed: u64,
    /// Attachments exported.
    pub attachments: u64,
    /// Links to a secret outside the export, left out.
    pub links_dropped: u64,
}

/// What an import created, in counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Secrets created.
    pub secrets: u64,
    /// Attachments stored.
    pub attachments: u64,
    /// Folder paths turned into tags.
    pub folders_as_tags: u64,
    /// Secrets the vault refused.
    pub refused: u64,
}

/// An export request.
#[derive(Clone, PartialEq, Eq)]
pub enum ExportRequest {
    /// 140.
    LockerExport {
        /// The locker.
        locker: Id16,
        /// Absolute path of the file to write.
        path: String,
        /// Export password; the core draws a passphrase when absent.
        password: Option<Zeroizing<String>>,
    },
    /// 141.
    LockerImport {
        /// Absolute path of the file to read.
        path: String,
        /// Its password.
        password: Zeroizing<String>,
        /// Name of the new locker; the name in the file when absent.
        name: Option<Zeroizing<String>>,
    },
}

impl std::fmt::Debug for ExportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: the password and the path are not for logs.
        write!(f, "ExportRequest::{}", self.op().name())
    }
}

/// A successful reply to an export request.
#[derive(Clone, PartialEq, Eq)]
pub enum ExportReply {
    /// 140.
    Exported {
        /// The passphrase the core drew, when the request gave no password. Shown once.
        password: Option<Zeroizing<String>>,
        /// Counts.
        report: ExportReport,
    },
    /// 141.
    Imported {
        /// The new locker.
        locker: Id16,
        /// Counts.
        report: ImportReport,
    },
}

impl std::fmt::Debug for ExportReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the passphrase.
        f.write_str(match self {
            ExportReply::Exported { .. } => "ExportReply::Exported",
            ExportReply::Imported { .. } => "ExportReply::Imported",
        })
    }
}

/// Whether `frame` is an export request: its operation code (key 3) is in [`EXPORT_OPS`].
#[must_use]
pub fn is_export_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| EXPORT_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ExportCode> {
    r.map_err(|_| ExportCode::General(ErrorCode::Malformed))
}

fn path_from(v: &Value) -> Result<String, ExportCode> {
    let p = m(text_max(v, MAX_PATH))?;
    if p.is_empty() {
        return Err(ExportCode::General(ErrorCode::InvalidInput));
    }
    Ok(p.to_owned())
}

fn password_from(v: &Value) -> Result<Zeroizing<String>, ExportCode> {
    let p = Zeroizing::new(m(text_max(v, MAX_PASSWORD))?.to_owned());
    if p.is_empty() {
        return Err(ExportCode::General(ErrorCode::InvalidInput));
    }
    Ok(p)
}

impl ExportRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> ExportOp {
        match self {
            ExportRequest::LockerExport { .. } => ExportOp::LockerExport,
            ExportRequest::LockerImport { .. } => ExportOp::LockerImport,
        }
    }

    fn args(&self) -> Value {
        match self {
            ExportRequest::LockerExport {
                locker,
                path,
                password,
            } => {
                let mut e = vec![(1, Value::bytes(locker)), (2, Value::text(path))];
                if let Some(p) = password {
                    e.push((3, Value::text(p)));
                }
                Value::map(e)
            }
            ExportRequest::LockerImport {
                path,
                password,
                name,
            } => {
                let mut e = vec![(1, Value::text(path)), (2, Value::text(password))];
                if let Some(n) = name {
                    e.push((3, Value::text(n)));
                }
                Value::map(e)
            }
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(EXPORT_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
            (4, self.args()),
        ]))
        .map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of an export request. Returns the identifier (0 if unreadable) with the
    /// code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, ExportRequest), (u64, ExportCode)> {
        let malformed = ExportCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != EXPORT_VERSION {
            return Err((id, ExportCode::General(ErrorCode::UnsupportedVersion)));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op =
            ExportOp::from_u64(op).ok_or((id, ExportCode::General(ErrorCode::UnknownOperation)))?;
        let args = f.opt(4).ok_or((id, malformed))?;
        Self::decode_args(op, args)
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: ExportOp, args: &Value) -> Result<ExportRequest, ExportCode> {
        match op {
            ExportOp::LockerExport => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                Ok(ExportRequest::LockerExport {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    path: path_from(m(f.req(2))?)?,
                    password: f.opt(3).map(password_from).transpose()?,
                })
            }
            ExportOp::LockerImport => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                let name = f
                    .opt(3)
                    .map(|n| {
                        let n = m(text_max(n, MAX_LOCKER_NAME))?;
                        if n.is_empty() {
                            return Err(ExportCode::General(ErrorCode::InvalidInput));
                        }
                        Ok(Zeroizing::new(n.to_owned()))
                    })
                    .transpose()?;
                Ok(ExportRequest::LockerImport {
                    path: path_from(m(f.req(1))?)?,
                    password: password_from(m(f.req(2))?)?,
                    name,
                })
            }
        }
    }
}

fn counts(values: [u64; 4]) -> Value {
    Value::map(
        (1u64..)
            .zip(values)
            .map(|(k, n)| (k, Value::Uint(n)))
            .collect(),
    )
}

fn counts_from(v: &Value) -> Result<[u64; 4], cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    Ok([
        f.req(1).and_then(uint)?,
        f.req(2).and_then(uint)?,
        f.req(3).and_then(uint)?,
        f.req(4).and_then(uint)?,
    ])
}

impl ExportReply {
    fn body(&self) -> Value {
        match self {
            ExportReply::Exported { password, report } => {
                let mut e = vec![(
                    2,
                    counts([
                        report.secrets,
                        report.trashed,
                        report.attachments,
                        report.links_dropped,
                    ]),
                )];
                if let Some(p) = password {
                    e.push((1, Value::text(p)));
                }
                Value::map(e)
            }
            ExportReply::Imported { locker, report } => Value::map(vec![
                (1, Value::bytes(locker)),
                (
                    2,
                    counts([
                        report.secrets,
                        report.attachments,
                        report.folders_as_tags,
                        report.refused,
                    ]),
                ),
            ]),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<ExportReply, ExportCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(EXPORT_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                e.push((4, r.body()));
            }
            Err(c) => {
                e.push((3, Value::Uint(c.status())));
                if *c == ExportCode::General(ErrorCode::UnsupportedVersion) {
                    e.push((
                        4,
                        Value::map(vec![(2, Value::Array(vec![Value::Uint(EXPORT_VERSION)]))]),
                    ));
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to an export request of operation `op` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: ExportOp,
        frame: &[u8],
    ) -> Result<(u64, Result<ExportReply, ExportCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        let version = f.req(1).and_then(uint).map_err(bad)?;
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        if status != 0 {
            // A core that does not speak version 9 answers in its own version.
            let code = ExportCode::from_status(status).ok_or(ErrorCode::Malformed)?;
            return Ok((id, Err(code)));
        }
        if version != EXPORT_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let body = f.req(4).map_err(bad)?;
        let reply = match op {
            ExportOp::LockerExport => {
                let b = Fields::new(body, &[1, 2]).map_err(bad)?;
                let [secrets, trashed, attachments, links_dropped] =
                    b.req(2).and_then(counts_from).map_err(bad)?;
                ExportReply::Exported {
                    password: b
                        .opt(1)
                        .map(|p| text_max(p, MAX_PASSWORD).map(|s| Zeroizing::new(s.to_owned())))
                        .transpose()
                        .map_err(bad)?,
                    report: ExportReport {
                        secrets,
                        trashed,
                        attachments,
                        links_dropped,
                    },
                }
            }
            ExportOp::LockerImport => {
                let b = Fields::new(body, &[1, 2]).map_err(bad)?;
                let [secrets, attachments, folders_as_tags, refused] =
                    b.req(2).and_then(counts_from).map_err(bad)?;
                ExportReply::Imported {
                    locker: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    report: ImportReport {
                        secrets,
                        attachments,
                        folders_as_tags,
                        refused,
                    },
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}

#[cfg(test)]
mod tests;
