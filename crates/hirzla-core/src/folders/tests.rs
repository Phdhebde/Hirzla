//! The folder operations, in process: wire round trips and strict decoding, the tree of each
//! locker, creating, renaming, moving and deleting folders, moving secrets; and a log that
//! never contains a folder name.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use super::proto::{
    is_folder_request, FolderOp, FolderReply, FolderRequest, LockerTree, WireFolder, FOLDER_VERSION,
};
use crate::events::Log;
use crate::proto::{ApiValue, ErrorCode, KdfParams, Reply, Request, Selector};
use crate::service::{Config, Core};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const FOLDER_NAME: &str = "Dossier-Confidentiel-4e2b";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn config(dir: &Path) -> Config {
    Config {
        vault_path: dir.join("coffre.hirzla"),
        auto_lock: None,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Applied,
            tracing_blocked: HardeningStatus::Applied,
        },
    }
}

fn open_core(dir: &Path) -> (Core, Sink) {
    let sink = Sink::default();
    let log = Arc::new(Log::new(Box::new(sink.clone())));
    let mut c = Core::new(config(dir), log);
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    (c, sink)
}

fn note(c: &mut Core, title: &str) -> (Id16, Id16) {
    match c
        .handle(Request::Create {
            locker: None,
            secret_type: SecretType::Note,
            fields: vec![(Field::Title, ApiValue::Text(z(title)))],
            urls: Vec::new(),
            tags: Vec::new(),
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        other => panic!("unexpected {other:?}"),
    }
}

fn mkdir(c: &mut Core, locker: Id16, name: &str, parent: Option<Id16>) -> Result<Id16, ErrorCode> {
    match c.handle_folder(FolderRequest::Create {
        locker,
        name: z(name),
        parent,
    })? {
        FolderReply::Created(id) => Ok(id),
        other => panic!("unexpected {other:?}"),
    }
}

fn tree(c: &mut Core, locker: Id16) -> LockerTree {
    match c
        .handle_folder(FolderRequest::Tree {
            locker: Some(locker),
        })
        .unwrap()
    {
        FolderReply::Trees(mut t) => {
            assert_eq!(t.len(), 1);
            t.remove(0)
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn mv(c: &mut Core, locker: Id16, secret: Id16, folder: Option<Id16>) -> Result<(), ErrorCode> {
    c.handle_folder(FolderRequest::SecretMove {
        locker,
        secret,
        folder,
    })
    .map(drop)
}

// -----------------------------------------------------------------------------------------
// Wire
// -----------------------------------------------------------------------------------------

#[test]
fn requests_and_replies_round_trip() {
    let requests = [
        FolderRequest::Tree { locker: None },
        FolderRequest::Tree {
            locker: Some([1; 16]),
        },
        FolderRequest::Create {
            locker: [1; 16],
            name: z("Banque"),
            parent: Some([2; 16]),
        },
        FolderRequest::Create {
            locker: [1; 16],
            name: z("Racine"),
            parent: None,
        },
        FolderRequest::Rename {
            locker: [1; 16],
            folder: [2; 16],
            name: z("Banques"),
        },
        FolderRequest::Move {
            locker: [1; 16],
            folder: [2; 16],
            parent: None,
        },
        FolderRequest::Delete {
            locker: [1; 16],
            folder: [2; 16],
        },
        FolderRequest::SecretMove {
            locker: [1; 16],
            secret: [3; 16],
            folder: Some([2; 16]),
        },
    ];
    for r in requests {
        let bytes = r.encode(7).unwrap();
        assert!(is_folder_request(&bytes));
        let (id, back) = FolderRequest::decode(&bytes).unwrap();
        assert_eq!(id, 7);
        assert!(back == r);
        assert!(!format!("{r:?}").contains("Banque"));
    }
    let replies = [
        (FolderOp::FolderRename, FolderReply::Done),
        (FolderOp::FolderCreate, FolderReply::Created([4; 16])),
        (FolderOp::FolderDelete, FolderReply::Trashed(3)),
        (
            FolderOp::FolderTree,
            FolderReply::Trees(vec![LockerTree {
                locker: [1; 16],
                folders: vec![
                    WireFolder {
                        id: [2; 16],
                        name: z("A"),
                        parent: None,
                    },
                    WireFolder {
                        id: [3; 16],
                        name: z("B"),
                        parent: Some([2; 16]),
                    },
                ],
                placements: vec![([5; 16], [3; 16])],
            }]),
        ),
    ];
    for (op, r) in replies {
        let bytes = FolderReply::encode(9, &Ok(r.clone())).unwrap();
        let (id, back) = FolderReply::decode(op, &bytes).unwrap();
        assert_eq!(id, 9);
        assert!(back.unwrap() == r);
    }
    let bytes = FolderReply::encode(9, &Err(ErrorCode::NotFound)).unwrap();
    let (_, back) = FolderReply::decode(FolderOp::FolderMove, &bytes).unwrap();
    assert_eq!(back.err(), Some(ErrorCode::NotFound));
}

fn frame(version: u64, op: u64, args: Option<Value>) -> Zeroizing<Vec<u8>> {
    let mut e = vec![
        (1, Value::Uint(version)),
        (2, Value::Uint(5)),
        (3, Value::Uint(op)),
    ];
    if let Some(a) = args {
        e.push((4, a));
    }
    cbor::encode(&Value::map(e)).unwrap()
}

#[test]
fn strict_decoding_refusals() {
    let refused = |v, op, args| FolderRequest::decode(&frame(v, op, args)).err().unwrap().1;
    let empty = || Some(Value::map(Vec::new()));
    assert_eq!(refused(8, 150, empty()), ErrorCode::UnsupportedVersion);
    assert_eq!(
        refused(FOLDER_VERSION, 159, empty()),
        ErrorCode::UnknownOperation
    );
    assert_eq!(refused(FOLDER_VERSION, 150, None), ErrorCode::Malformed);
    // Unknown key, short identifier, missing name.
    let unknown = Some(Value::map(vec![(9, Value::Uint(1))]));
    assert_eq!(refused(FOLDER_VERSION, 150, unknown), ErrorCode::Malformed);
    let short = Some(Value::map(vec![(1, Value::bytes(&[1; 15]))]));
    assert_eq!(refused(FOLDER_VERSION, 150, short), ErrorCode::Malformed);
    let no_name = Some(Value::map(vec![(1, Value::bytes(&[1; 16]))]));
    assert_eq!(refused(FOLDER_VERSION, 151, no_name), ErrorCode::Malformed);
    // An unsupported version is answered with the version spoken.
    let bytes = FolderReply::encode(5, &Err(ErrorCode::UnsupportedVersion)).unwrap();
    let v = cbor::decode(&bytes).unwrap();
    assert!(format!("{v:?}").contains("Map"));
}

// -----------------------------------------------------------------------------------------
// Behaviour
// -----------------------------------------------------------------------------------------

#[test]
fn folders_and_secret_moves_in_the_vault() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let (l, s) = note(&mut c, "compte");
    let bank = mkdir(&mut c, l, FOLDER_NAME, None).unwrap();
    let pro = mkdir(&mut c, l, "Pro", Some(bank)).unwrap();
    let other = mkdir(&mut c, l, "autre", None).unwrap();
    mv(&mut c, l, s, Some(pro)).unwrap();
    let t = tree(&mut c, l);
    // Sorted by name without case: "autre", the confidential name, "Pro".
    let names: Vec<&str> = t.folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["autre", FOLDER_NAME, "Pro"]);
    assert_eq!(t.folders[2].parent, Some(bank));
    assert_eq!(t.placements, vec![(s, pro)]);

    c.handle_folder(FolderRequest::Move {
        locker: l,
        folder: pro,
        parent: Some(other),
    })
    .unwrap();
    c.handle_folder(FolderRequest::Rename {
        locker: l,
        folder: other,
        name: z("Autres"),
    })
    .unwrap();
    let t = tree(&mut c, l);
    let pro_node = t.folders.iter().find(|f| f.id == pro).unwrap();
    assert_eq!(pro_node.parent, Some(other));

    // Writer's rules.
    assert_eq!(
        mkdir(&mut c, l, "", None).err(),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(
        mkdir(&mut c, l, "x", Some([9; 16])).err(),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(
        c.handle_folder(FolderRequest::Move {
            locker: l,
            folder: other,
            parent: Some(pro),
        })
        .err(),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(
        mv(&mut c, l, s, Some([9; 16])).err(),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(
        mv(&mut c, l, [8; 16], None).err(),
        Some(ErrorCode::NotFound)
    );
    assert_eq!(
        mkdir(&mut c, [7; 16], "x", None).err(),
        Some(ErrorCode::NotFound)
    );

    // Deleting a folder puts the active secrets of its subtree in the trash.
    let n = c
        .handle_folder(FolderRequest::Delete {
            locker: l,
            folder: other,
        })
        .unwrap();
    assert!(n == FolderReply::Trashed(1));
    let t = tree(&mut c, l);
    assert_eq!(t.folders.len(), 1);
    // The trashed secret, whose folder is gone, shows at the root: no placement.
    assert!(t.placements.is_empty());
    let read = c.handle(Request::Read {
        selector: Selector::Id { locker: l, id: s },
        field: Field::Title,
    });
    assert!(read.is_ok());

    // The log names operations and results only.
    let log = sink.text();
    assert!(log.contains("event=folder_request op=folder_create result=ok"));
    assert!(log.contains("event=folder_request op=secret_move result=invalid_input"));
    assert!(!log.contains(FOLDER_NAME));
}

#[test]
fn a_locked_or_absent_vault_refuses() {
    let dir = tempdir();
    let sink = Sink::default();
    let mut c = Core::new(
        config(dir.path()),
        Arc::new(Log::new(Box::new(sink.clone()))),
    );
    let t = || FolderRequest::Tree { locker: None };
    assert_eq!(c.handle_folder(t()).err(), Some(ErrorCode::NoVault));
    drop(c);
    let (mut c, sink) = open_core(dir.path());
    c.handle(Request::Lock).unwrap();
    assert_eq!(c.handle_folder(t()).err(), Some(ErrorCode::Locked));
    assert!(sink
        .text()
        .contains("event=folder_request op=folder_tree result=locked"));
}
