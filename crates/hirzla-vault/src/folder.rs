//! Folders inside a locker (`docs/format.md` § 7.5, ADR 0076, format version 3).
//!
//! A folder is an object of the locker metadata (`LockerBody`, key 3): a name, a parent and a
//! state, three registers merged by the largest stamp. Folders are never removed from the map:
//! deleting one sets its state. The tree shown to the user is a pure function of the merged
//! map, computed by [`FolderTree::of`]: cycles left by concurrent moves are broken by
//! detaching the folder whose move is the latest in the total order, and the contents of a
//! deleted folder show in its nearest active ancestor. Nothing is written to resolve them.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::cbor::{fixed, text_max, uint_in, CborError, Fields, Value};
use crate::model::{Id16, Stamp};
use crate::secret::EditError;

/// Most folders in one locker, deleted ones included.
pub const MAX_FOLDERS: usize = 2048;
/// Longest folder name, in bytes.
pub const MAX_FOLDER_NAME: usize = 255;
/// Deepest folder a writer creates (a top-level folder has depth 1).
pub const MAX_FOLDER_DEPTH: usize = 32;

/// Whether `name` is an acceptable folder name: 1 to 255 bytes, no control character.
#[must_use]
pub fn is_valid_folder_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_FOLDER_NAME && !name.chars().any(char::is_control)
}

/// A folder: three registers, each with the stamp of the write that set it.
#[derive(Clone, PartialEq, Eq)]
pub struct Folder {
    /// Name.
    pub name: (Zeroizing<String>, Stamp),
    /// Parent folder; `None` is the root of the locker.
    pub parent: (Option<Id16>, Stamp),
    /// Deleted.
    pub deleted: (bool, Stamp),
}

/// The folders of a locker, by identifier.
pub type Folders = BTreeMap<Id16, Folder>;

/// Canonical value of a folder map (`LockerBody` key 3, `IndexShard` key 6).
#[must_use]
pub fn folders_to_value(folders: &Folders) -> Value {
    Value::Map(
        folders
            .iter()
            .map(|(id, f)| {
                let parent = match &f.parent.0 {
                    Some(p) => Value::bytes(p),
                    None => Value::Null,
                };
                (
                    Value::bytes(id),
                    Value::map(vec![
                        (
                            1,
                            Value::map(vec![(1, Value::text(&f.name.0)), (2, f.name.1.to_value())]),
                        ),
                        (2, Value::map(vec![(1, parent), (2, f.parent.1.to_value())])),
                        (
                            3,
                            Value::map(vec![
                                (1, Value::Uint(u64::from(f.deleted.0))),
                                (2, f.deleted.1.to_value()),
                            ]),
                        ),
                    ]),
                )
            })
            .collect(),
    )
}

/// Strict decoding of a folder map: 1 to [`MAX_FOLDERS`] folders, valid names, and every
/// parent is another folder of the map.
///
/// # Errors
/// [`CborError`].
pub fn folders_from_value(v: &Value) -> Result<Folders, CborError> {
    let Value::Map(entries) = v else {
        return Err(CborError::Malformed);
    };
    if entries.is_empty() || entries.len() > MAX_FOLDERS {
        return Err(CborError::Malformed);
    }
    let mut out = Folders::new();
    for (k, e) in entries {
        let id = fixed::<16>(k)?;
        let f = Fields::new(e, &[1, 2, 3])?;
        let entry = |v: &Value| -> Result<(Value, Stamp), CborError> {
            let ef = Fields::new(v, &[1, 2])?;
            Ok((ef.req(1)?.clone(), Stamp::from_value(ef.req(2)?)?))
        };
        let (name, name_stamp) = entry(f.req(1)?)?;
        let name = text_max(&name, MAX_FOLDER_NAME)?;
        if !is_valid_folder_name(name) {
            return Err(CborError::Malformed);
        }
        let (parent, parent_stamp) = entry(f.req(2)?)?;
        let parent = match &parent {
            Value::Null => None,
            p => Some(fixed::<16>(p)?),
        };
        let (state, state_stamp) = entry(f.req(3)?)?;
        let deleted = uint_in(&state, 0..=1)? == 1;
        out.insert(
            id,
            Folder {
                name: (Zeroizing::new(name.to_owned()), name_stamp),
                parent: (parent, parent_stamp),
                deleted: (deleted, state_stamp),
            },
        );
    }
    for (id, f) in &out {
        if let Some(p) = f.parent.0 {
            if p == *id || !out.contains_key(&p) {
                return Err(CborError::Malformed);
            }
        }
    }
    Ok(out)
}

/// Merges `other` into `into`: union of folders, largest stamp per register
/// (`sync-protocol.md` § 8.2).
pub fn merge_folders(into: &mut Folders, other: &Folders) {
    for (id, f) in other {
        match into.get_mut(id) {
            None => {
                into.insert(*id, f.clone());
            }
            Some(cur) => {
                if f.name.1 > cur.name.1 {
                    cur.name = f.name.clone();
                }
                if f.parent.1 > cur.parent.1 {
                    cur.parent = f.parent;
                }
                if f.deleted.1 > cur.deleted.1 {
                    cur.deleted = f.deleted;
                }
            }
        }
    }
}

/// Whether `body` keeps every folder of `merged` and changes only registers carrying `own`
/// (`sync-protocol.md` § 8.1): a version may not drop a folder nor attribute a value to
/// another write. With no merged parents, every register must carry `own`.
#[must_use]
pub fn folders_written_by(body: &Folders, merged: Option<&Folders>, own: Stamp) -> bool {
    let empty = Folders::new();
    let m = merged.unwrap_or(&empty);
    if m.keys().any(|id| !body.contains_key(id)) {
        return false;
    }
    body.iter().all(|(id, f)| match m.get(id) {
        None => f.name.1 == own && f.parent.1 == own && f.deleted.1 == own,
        Some(p) => {
            (f.name.1 == own || f.name == p.name)
                && (f.parent.1 == own || f.parent == p.parent)
                && (f.deleted.1 == own || f.deleted == p.deleted)
        }
    })
}

/// A change to the folders of a locker.
#[derive(Clone, PartialEq, Eq)]
pub enum FolderEdit {
    /// Creates a folder under `parent` (`None`: the root).
    Create {
        /// New identifier, drawn by the caller from the system's randomness.
        id: Id16,
        /// Name.
        name: Zeroizing<String>,
        /// Parent.
        parent: Option<Id16>,
    },
    /// Renames a folder.
    Rename {
        /// Folder.
        id: Id16,
        /// New name.
        name: Zeroizing<String>,
    },
    /// Moves a folder under `parent` (`None`: the root).
    Move {
        /// Folder.
        id: Id16,
        /// New parent.
        parent: Option<Id16>,
    },
    /// Deletes a folder and every folder under it.
    Delete {
        /// Folder.
        id: Id16,
    },
}

/// Applies folder edits in order, under the writer's rules (ADR 0076 § 4): names valid,
/// parents active, no folder under itself, depth at most [`MAX_FOLDER_DEPTH`], at most
/// [`MAX_FOLDERS`] folders. Every register changed carries `stamp`.
///
/// Before the edits, a folder that the shown tree detached to break a cycle is written at
/// the root: the stored parents then describe the tree the writer checked.
///
/// # Errors
/// [`EditError::NotAllowed`].
pub fn edit_folders(
    folders: &mut Folders,
    edits: Vec<FolderEdit>,
    stamp: Stamp,
) -> Result<(), EditError> {
    for id in FolderTree::of(folders).detached {
        if let Some(f) = folders.get_mut(&id) {
            f.parent = (None, stamp);
        }
    }
    for e in edits {
        let tree = FolderTree::of(folders);
        match e {
            FolderEdit::Create { id, name, parent } => {
                if folders.contains_key(&id)
                    || folders.len() >= MAX_FOLDERS
                    || !is_valid_folder_name(&name)
                    || tree
                        .depth_under(parent)
                        .is_none_or(|d| d >= MAX_FOLDER_DEPTH)
                {
                    return Err(EditError::NotAllowed);
                }
                folders.insert(
                    id,
                    Folder {
                        name: (name, stamp),
                        parent: (parent, stamp),
                        deleted: (false, stamp),
                    },
                );
            }
            FolderEdit::Rename { id, name } => {
                if !tree.contains(&id) || !is_valid_folder_name(&name) {
                    return Err(EditError::NotAllowed);
                }
                if let Some(f) = folders.get_mut(&id) {
                    f.name = (name, stamp);
                }
            }
            FolderEdit::Move { id, parent } => {
                if !tree.contains(&id) {
                    return Err(EditError::NotAllowed);
                }
                if let Some(p) = parent {
                    if p == id || tree.descendants(&id).contains(&p) {
                        return Err(EditError::NotAllowed);
                    }
                }
                let base = tree.depth_under(parent).ok_or(EditError::NotAllowed)?;
                if base + tree.height(&id) > MAX_FOLDER_DEPTH {
                    return Err(EditError::NotAllowed);
                }
                if let Some(f) = folders.get_mut(&id) {
                    f.parent = (parent, stamp);
                }
            }
            FolderEdit::Delete { id } => {
                if !tree.contains(&id) {
                    return Err(EditError::NotAllowed);
                }
                let mut gone = tree.descendants(&id);
                gone.insert(id);
                for g in gone {
                    if let Some(f) = folders.get_mut(&g) {
                        f.deleted = (true, stamp);
                    }
                }
            }
        }
    }
    Ok(())
}

/// An active folder of the shown tree.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeFolder {
    /// Name.
    pub name: Zeroizing<String>,
    /// Shown parent: an active folder, or `None` for the root.
    pub parent: Option<Id16>,
    /// Depth: 1 under the root.
    pub depth: usize,
}

/// The tree shown to the user, computed from the merged folders (ADR 0076 § 3). Two replicas
/// with the same merged state compute the same tree.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct FolderTree {
    /// Active folders.
    folders: BTreeMap<Id16, TreeFolder>,
    /// Every known folder, deleted ones included, to the active folder where its contents
    /// show (`None`: the root).
    shown_in: BTreeMap<Id16, Option<Id16>>,
    /// Folders detached to the root to break a cycle.
    detached: BTreeSet<Id16>,
}

impl FolderTree {
    /// Computes the shown tree.
    #[must_use]
    pub fn of(folders: &Folders) -> FolderTree {
        // 1. Effective parents: stored parents, with cycles broken. Each folder has one
        // parent, so cycles are disjoint; in each, the folder whose parent register carries
        // the largest stamp goes to the root.
        let mut parent: BTreeMap<Id16, Option<Id16>> = folders
            .iter()
            .map(|(id, f)| (*id, f.parent.0.filter(|p| folders.contains_key(p))))
            .collect();
        let mut detached = BTreeSet::new();
        let mut done: BTreeSet<Id16> = BTreeSet::new();
        for start in folders.keys() {
            if done.contains(start) {
                continue;
            }
            let mut path: Vec<Id16> = Vec::new();
            let mut on_path: BTreeSet<Id16> = BTreeSet::new();
            let mut cur = Some(*start);
            while let Some(c) = cur {
                if done.contains(&c) {
                    break;
                }
                if on_path.contains(&c) {
                    // The cycle is the part of the path from `c` on.
                    let pos = path.iter().position(|x| *x == c).unwrap_or(0);
                    let cycle = &path[pos..];
                    let loser = cycle
                        .iter()
                        .max_by_key(|id| folders.get(*id).map(|f| f.parent.1))
                        .copied();
                    if let Some(l) = loser {
                        parent.insert(l, None);
                        detached.insert(l);
                    }
                    break;
                }
                path.push(c);
                on_path.insert(c);
                cur = parent.get(&c).copied().flatten();
            }
            done.extend(path);
        }
        // 2. Where the contents of each folder show: itself if active, else the place of its
        // effective parent. The graph is now acyclic.
        let mut shown_in: BTreeMap<Id16, Option<Id16>> = BTreeMap::new();
        for id in folders.keys() {
            let mut chain = Vec::new();
            let mut cur = Some(*id);
            let mut found: Option<Id16> = None;
            while let Some(c) = cur {
                if let Some(known) = shown_in.get(&c) {
                    found = *known;
                    break;
                }
                if folders.get(&c).is_some_and(|f| !f.deleted.0) {
                    found = Some(c);
                    break;
                }
                chain.push(c);
                cur = parent.get(&c).copied().flatten();
            }
            for c in chain {
                shown_in.insert(c, found);
            }
            if found == Some(*id) {
                shown_in.insert(*id, found);
            }
        }
        // 3. Active folders under their shown parent, with their depth.
        let mut out: BTreeMap<Id16, TreeFolder> = BTreeMap::new();
        for (id, f) in folders {
            if f.deleted.0 {
                continue;
            }
            let shown_parent = parent
                .get(id)
                .copied()
                .flatten()
                .and_then(|p| shown_in.get(&p).copied().flatten());
            out.insert(
                *id,
                TreeFolder {
                    name: f.name.0.clone(),
                    parent: shown_parent,
                    depth: 0,
                },
            );
        }
        let ids: Vec<Id16> = out.keys().copied().collect();
        for id in ids {
            let mut depth = 0;
            let mut cur = Some(id);
            while let Some(c) = cur {
                depth += 1;
                cur = out.get(&c).and_then(|f| f.parent);
                if depth > folders.len() {
                    break; // unreachable: the shown tree is acyclic
                }
            }
            if let Some(f) = out.get_mut(&id) {
                f.depth = depth;
            }
        }
        FolderTree {
            folders: out,
            shown_in,
            detached,
        }
    }

    /// Whether `id` is an active folder.
    #[must_use]
    pub fn contains(&self, id: &Id16) -> bool {
        self.folders.contains_key(id)
    }

    /// The active folder `id`.
    #[must_use]
    pub fn get(&self, id: &Id16) -> Option<&TreeFolder> {
        self.folders.get(id)
    }

    /// Active folders, by identifier.
    pub fn iter(&self) -> impl Iterator<Item = (&Id16, &TreeFolder)> {
        self.folders.iter()
    }

    /// Number of active folders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.folders.len()
    }

    /// Whether there is no active folder.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty()
    }

    /// Where a secret whose `folder` field holds `field` shows: the active folder, or `None`
    /// for the root. An unknown folder shows at the root (ADR 0076 § 3.3).
    #[must_use]
    pub fn place(&self, field: Option<Id16>) -> Option<Id16> {
        field.and_then(|f| self.shown_in.get(&f).copied().flatten())
    }

    /// Active folders under `id`, at any depth.
    #[must_use]
    pub fn descendants(&self, id: &Id16) -> BTreeSet<Id16> {
        let mut out = BTreeSet::new();
        let mut todo = vec![*id];
        while let Some(c) = todo.pop() {
            for (k, f) in &self.folders {
                if f.parent == Some(c) && out.insert(*k) {
                    todo.push(*k);
                }
            }
        }
        out
    }

    /// Names from the top-level folder down to `id`; empty for the root or an unknown folder.
    #[must_use]
    pub fn path(&self, id: Option<Id16>) -> Vec<&str> {
        let mut out = Vec::new();
        let mut cur = id;
        while let Some(c) = cur {
            let Some(f) = self.folders.get(&c) else {
                break;
            };
            out.push(f.name.as_str());
            cur = f.parent;
            if out.len() > self.folders.len() {
                break;
            }
        }
        out.reverse();
        out
    }

    /// Depth a new child of `parent` would have minus one: 0 under the root, `None` if the
    /// parent is not an active folder.
    fn depth_under(&self, parent: Option<Id16>) -> Option<usize> {
        match parent {
            None => Some(0),
            Some(p) => self.folders.get(&p).map(|f| f.depth),
        }
    }

    /// Levels of the subtree rooted at `id`, itself included.
    fn height(&self, id: &Id16) -> usize {
        let base = self.folders.get(id).map_or(0, |f| f.depth);
        self.descendants(id)
            .iter()
            .filter_map(|d| self.folders.get(d))
            .map(|f| f.depth - base)
            .max()
            .unwrap_or(0)
            + 1
    }
}

#[cfg(test)]
mod tests;
