//! Folder operations of the local API (`docs/api-locale.md` § 20): version 11, operation codes
//! 150 to 159. Same frames, same CBOR profile and same strict decoding as the rest of the API
//! (`crate::proto`). The general error codes of § 7 are the only ones used.

use hirzla_vault::cbor::{self, array_max, fixed, text_max, uint, Fields, Value};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::proto::ErrorCode;

/// Version of the protocol that carries the folder operations.
pub const FOLDER_VERSION: u64 = 11;
/// Operation codes reserved for folders.
pub const FOLDER_OPS: std::ops::RangeInclusive<u64> = 150..=159;
/// Longest folder name on the wire; the vault refuses more than 255 bytes.
const MAX_NAME: usize = 4096;
/// Most folders and placements in one locker of a reply.
const MAX_ITEMS: usize = 1 << 20;
/// Most lockers in a reply.
const MAX_LOCKERS: usize = 1 << 16;

/// Folder operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderOp {
    /// The shown tree of each locker, and where its secrets are.
    FolderTree = 150,
    /// Create a folder.
    FolderCreate = 151,
    /// Rename a folder.
    FolderRename = 152,
    /// Move a folder.
    FolderMove = 153,
    /// Delete a folder and its sub-folders; their active secrets go to the trash.
    FolderDelete = 154,
    /// Put a secret in a folder of its locker, or at its root.
    SecretMove = 155,
}

impl FolderOp {
    /// All operations.
    pub const ALL: [FolderOp; 6] = [
        FolderOp::FolderTree,
        FolderOp::FolderCreate,
        FolderOp::FolderRename,
        FolderOp::FolderMove,
        FolderOp::FolderDelete,
        FolderOp::SecretMove,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<FolderOp> {
        FolderOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FolderOp::FolderTree => "folder_tree",
            FolderOp::FolderCreate => "folder_create",
            FolderOp::FolderRename => "folder_rename",
            FolderOp::FolderMove => "folder_move",
            FolderOp::FolderDelete => "folder_delete",
            FolderOp::SecretMove => "secret_move",
        }
    }
}

/// An active folder of a shown tree (§ 20.2).
#[derive(Clone, PartialEq, Eq)]
pub struct WireFolder {
    /// Identifier.
    pub id: Id16,
    /// Name.
    pub name: Zeroizing<String>,
    /// Shown parent; `None`: the root of the locker.
    pub parent: Option<Id16>,
}

/// The shown tree of one locker and the secrets that are not at its root.
#[derive(Clone, PartialEq, Eq)]
pub struct LockerTree {
    /// Locker.
    pub locker: Id16,
    /// Active folders, by name without case, then identifier.
    pub folders: Vec<WireFolder>,
    /// `(secret, folder)` for each secret, purged ones excepted, shown in a folder; sorted by
    /// secret.
    pub placements: Vec<(Id16, Id16)>,
}

/// A folder request.
#[derive(Clone, PartialEq, Eq)]
pub enum FolderRequest {
    /// `FolderTree`, of one locker or of all.
    Tree {
        /// Locker; `None`: every locker.
        locker: Option<Id16>,
    },
    /// `FolderCreate`.
    Create {
        /// Locker.
        locker: Id16,
        /// Name.
        name: Zeroizing<String>,
        /// Parent; `None`: the root.
        parent: Option<Id16>,
    },
    /// `FolderRename`.
    Rename {
        /// Locker.
        locker: Id16,
        /// Folder.
        folder: Id16,
        /// New name.
        name: Zeroizing<String>,
    },
    /// `FolderMove`.
    Move {
        /// Locker.
        locker: Id16,
        /// Folder.
        folder: Id16,
        /// New parent; `None`: the root.
        parent: Option<Id16>,
    },
    /// `FolderDelete`.
    Delete {
        /// Locker.
        locker: Id16,
        /// Folder.
        folder: Id16,
    },
    /// `SecretMove`.
    SecretMove {
        /// Locker.
        locker: Id16,
        /// Secret.
        secret: Id16,
        /// Folder; `None`: the root.
        folder: Option<Id16>,
    },
}

impl std::fmt::Debug for FolderRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: folder names are not for logs.
        write!(f, "FolderRequest::{}", self.op().name())
    }
}

/// A folder reply.
#[derive(Clone, PartialEq, Eq)]
pub enum FolderReply {
    /// Nothing to return.
    Done,
    /// The trees asked for.
    Trees(Vec<LockerTree>),
    /// The new folder.
    Created(Id16),
    /// The number of secrets put in the trash.
    Trashed(u64),
}

impl std::fmt::Debug for FolderReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FolderReply::Done => "FolderReply::Done",
            FolderReply::Trees(_) => "FolderReply::Trees",
            FolderReply::Created(_) => "FolderReply::Created",
            FolderReply::Trashed(_) => "FolderReply::Trashed",
        })
    }
}

/// Whether a frame carries a folder operation (code 150 to 159), whatever its version.
#[must_use]
pub fn is_folder_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| FOLDER_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ErrorCode> {
    r.map_err(|_| ErrorCode::Malformed)
}

fn name_from(v: &Value) -> Result<Zeroizing<String>, cbor::CborError> {
    text_max(v, MAX_NAME).map(|s| Zeroizing::new(s.to_owned()))
}

impl FolderRequest {
    /// The operation code.
    #[must_use]
    pub fn op(&self) -> FolderOp {
        match self {
            FolderRequest::Tree { .. } => FolderOp::FolderTree,
            FolderRequest::Create { .. } => FolderOp::FolderCreate,
            FolderRequest::Rename { .. } => FolderOp::FolderRename,
            FolderRequest::Move { .. } => FolderOp::FolderMove,
            FolderRequest::Delete { .. } => FolderOp::FolderDelete,
            FolderRequest::SecretMove { .. } => FolderOp::SecretMove,
        }
    }

    fn args(&self) -> Value {
        let opt = |e: &mut Vec<(u64, Value)>, k: u64, v: &Option<Id16>| {
            if let Some(id) = v {
                e.push((k, Value::bytes(id)));
            }
        };
        let mut e = Vec::new();
        match self {
            FolderRequest::Tree { locker } => opt(&mut e, 1, locker),
            FolderRequest::Create {
                locker,
                name,
                parent,
            } => {
                e.push((1, Value::bytes(locker)));
                e.push((2, Value::text(name)));
                opt(&mut e, 3, parent);
            }
            FolderRequest::Rename {
                locker,
                folder,
                name,
            } => {
                e.push((1, Value::bytes(locker)));
                e.push((2, Value::bytes(folder)));
                e.push((3, Value::text(name)));
            }
            FolderRequest::Move {
                locker,
                folder,
                parent,
            } => {
                e.push((1, Value::bytes(locker)));
                e.push((2, Value::bytes(folder)));
                opt(&mut e, 3, parent);
            }
            FolderRequest::Delete { locker, folder } => {
                e.push((1, Value::bytes(locker)));
                e.push((2, Value::bytes(folder)));
            }
            FolderRequest::SecretMove {
                locker,
                secret,
                folder,
            } => {
                e.push((1, Value::bytes(locker)));
                e.push((2, Value::bytes(secret)));
                opt(&mut e, 3, folder);
            }
        }
        Value::map(e)
    }

    /// Encodes the request with identifier `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(FOLDER_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
            (4, self.args()),
        ]))
        .map_err(|_| ErrorCode::Internal)
    }

    /// Decodes a request frame. The error carries the request identifier (0 if unknown).
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, FolderRequest), (u64, ErrorCode)> {
        let malformed = ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != FOLDER_VERSION {
            return Err((id, ErrorCode::UnsupportedVersion));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op = FolderOp::from_u64(op).ok_or((id, ErrorCode::UnknownOperation))?;
        let args = f.opt(4).ok_or((id, malformed))?;
        Self::decode_args(op, args)
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: FolderOp, args: &Value) -> Result<FolderRequest, ErrorCode> {
        let id16 = |f: &Fields<'_>, k: u64| m(f.req(k).and_then(fixed::<16>));
        let opt16 = |f: &Fields<'_>, k: u64| m(f.opt(k).map(fixed::<16>).transpose());
        Ok(match op {
            FolderOp::FolderTree => {
                let f = m(Fields::new(args, &[1]))?;
                FolderRequest::Tree {
                    locker: opt16(&f, 1)?,
                }
            }
            FolderOp::FolderCreate => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                FolderRequest::Create {
                    locker: id16(&f, 1)?,
                    name: m(f.req(2).and_then(name_from))?,
                    parent: opt16(&f, 3)?,
                }
            }
            FolderOp::FolderRename => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                FolderRequest::Rename {
                    locker: id16(&f, 1)?,
                    folder: id16(&f, 2)?,
                    name: m(f.req(3).and_then(name_from))?,
                }
            }
            FolderOp::FolderMove => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                FolderRequest::Move {
                    locker: id16(&f, 1)?,
                    folder: id16(&f, 2)?,
                    parent: opt16(&f, 3)?,
                }
            }
            FolderOp::FolderDelete => {
                let f = m(Fields::new(args, &[1, 2]))?;
                FolderRequest::Delete {
                    locker: id16(&f, 1)?,
                    folder: id16(&f, 2)?,
                }
            }
            FolderOp::SecretMove => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                FolderRequest::SecretMove {
                    locker: id16(&f, 1)?,
                    secret: id16(&f, 2)?,
                    folder: opt16(&f, 3)?,
                }
            }
        })
    }
}

fn tree_value(t: &LockerTree) -> Value {
    let folders = t
        .folders
        .iter()
        .map(|f| {
            let mut e = vec![(1, Value::bytes(&f.id)), (2, Value::text(&f.name))];
            if let Some(p) = &f.parent {
                e.push((3, Value::bytes(p)));
            }
            Value::map(e)
        })
        .collect();
    let placements = t
        .placements
        .iter()
        .map(|(s, f)| Value::map(vec![(1, Value::bytes(s)), (2, Value::bytes(f))]))
        .collect();
    Value::map(vec![
        (1, Value::bytes(&t.locker)),
        (2, Value::Array(folders)),
        (3, Value::Array(placements)),
    ])
}

fn tree_from(v: &Value) -> Result<LockerTree, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3])?;
    let folders = array_max(f.req(2)?, MAX_ITEMS)?
        .iter()
        .map(|x| {
            let g = Fields::new(x, &[1, 2, 3])?;
            Ok(WireFolder {
                id: fixed::<16>(g.req(1)?)?,
                name: name_from(g.req(2)?)?,
                parent: g.opt(3).map(fixed::<16>).transpose()?,
            })
        })
        .collect::<Result<_, cbor::CborError>>()?;
    let placements = array_max(f.req(3)?, MAX_ITEMS)?
        .iter()
        .map(|x| {
            let g = Fields::new(x, &[1, 2])?;
            Ok((fixed::<16>(g.req(1)?)?, fixed::<16>(g.req(2)?)?))
        })
        .collect::<Result<_, cbor::CborError>>()?;
    Ok(LockerTree {
        locker: fixed::<16>(f.req(1)?)?,
        folders,
        placements,
    })
}

impl FolderReply {
    fn body(&self) -> Option<Value> {
        match self {
            FolderReply::Done => None,
            FolderReply::Trees(t) => Some(Value::map(vec![(
                1,
                Value::Array(t.iter().map(tree_value).collect()),
            )])),
            FolderReply::Created(id) => Some(Value::map(vec![(1, Value::bytes(id))])),
            FolderReply::Trashed(n) => Some(Value::map(vec![(1, Value::Uint(*n))])),
        }
    }

    /// Encodes a reply to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<FolderReply, ErrorCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(FOLDER_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err(c) => {
                e.push((3, Value::Uint(*c as u64)));
                if *c == ErrorCode::UnsupportedVersion {
                    e.push((
                        4,
                        Value::map(vec![(2, Value::Array(vec![Value::Uint(FOLDER_VERSION)]))]),
                    ));
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to an operation `op`.
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`] for a reply that does not follow the protocol.
    pub fn decode(
        op: FolderOp,
        frame: &[u8],
    ) -> Result<(u64, Result<FolderReply, ErrorCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        if f.req(1).and_then(uint).map_err(bad)? != FOLDER_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        if status != 0 {
            let code = ErrorCode::from_u64(status).ok_or(ErrorCode::Malformed)?;
            return Ok((id, Err(code)));
        }
        let body = || f.opt(4).ok_or(ErrorCode::Malformed);
        let reply = match op {
            FolderOp::FolderRename | FolderOp::FolderMove | FolderOp::SecretMove => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                FolderReply::Done
            }
            FolderOp::FolderTree => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                FolderReply::Trees(
                    b.req(1)
                        .and_then(|l| array_max(l, MAX_LOCKERS))
                        .map_err(bad)?
                        .iter()
                        .map(tree_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                )
            }
            FolderOp::FolderCreate => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                FolderReply::Created(b.req(1).and_then(fixed::<16>).map_err(bad)?)
            }
            FolderOp::FolderDelete => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                FolderReply::Trashed(b.req(1).and_then(uint).map_err(bad)?)
            }
        };
        Ok((id, Ok(reply)))
    }
}
