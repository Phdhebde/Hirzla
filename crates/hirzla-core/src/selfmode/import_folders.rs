//! KeePass groups as folders of the target locker (ADR 0076 § 11).
//!
//! The root group of the database is the root of the locker; every other group becomes a
//! folder with its name and its place in the tree. The folders are created by a single
//! locker metadata write, before the entries; each entry is then created in its folder.
//!
//! Limits of the vault (`format.md` § 7.5), so that nothing but the arrangement is lost:
//!
//! - beyond 32 levels, deeper groups are merged into their ancestor of level 32;
//! - beyond 2 048 groups, the next ones (document order) are merged into their created
//!   parent;
//! - a name loses its control characters and surrounding spaces, an empty one becomes
//!   « Sans nom », a longer one is cut at 255 bytes on a character boundary.
//!
//! Groups are known from the paths of the entries: a group with no entry under it at any
//! depth is not seen, and two sibling groups of the same name become one folder.

use hirzla_vault::folder::{FolderEdit, MAX_FOLDERS, MAX_FOLDER_DEPTH, MAX_FOLDER_NAME};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

/// Name given to a group whose name is empty once cleaned.
const UNNAMED: &str = "Sans nom";

/// The name a group gets as a folder.
pub(crate) fn folder_name(group: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(group.len().min(MAX_FOLDER_NAME)));
    for c in group.chars().filter(|c| !c.is_control()) {
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        return Zeroizing::new(UNNAMED.to_owned());
    }
    let mut end = trimmed.len().min(MAX_FOLDER_NAME);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let cut = trimmed[..end].trim_end();
    Zeroizing::new(if cut.is_empty() {
        UNNAMED.to_owned()
    } else {
        cut.to_owned()
    })
}

struct Node {
    name: Zeroizing<String>,
    parent: Option<usize>,
    id: Id16,
}

/// The folders made from the groups of a database.
#[derive(Default)]
pub(crate) struct GroupFolders {
    nodes: Vec<Node>,
}

impl GroupFolders {
    /// The folders for these group paths (root group excluded, outermost first), in the
    /// order given. `draw` gives a fresh identifier for each folder.
    ///
    /// # Errors
    /// The error of `draw`.
    pub(crate) fn plan<'a, E>(
        paths: impl IntoIterator<Item = &'a [Zeroizing<String>]>,
        mut draw: impl FnMut() -> Result<Id16, E>,
    ) -> Result<GroupFolders, E> {
        let mut out = GroupFolders::default();
        for path in paths {
            let mut at: Option<usize> = None;
            for group in path.iter().take(MAX_FOLDER_DEPTH) {
                let name = folder_name(group);
                at = match out.child(at, &name) {
                    Some(i) => Some(i),
                    // Past the limit, the group is merged into its created parent.
                    None if out.nodes.len() >= MAX_FOLDERS => at,
                    None => {
                        out.nodes.push(Node {
                            name,
                            parent: at,
                            id: draw()?,
                        });
                        Some(out.nodes.len() - 1)
                    }
                };
            }
        }
        Ok(out)
    }

    fn child(&self, parent: Option<usize>, name: &str) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.parent == parent && n.name.as_str() == name)
    }

    /// Number of folders.
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    /// The edits that create every folder, parents first.
    pub(crate) fn edits(&self) -> Vec<FolderEdit> {
        self.nodes
            .iter()
            .map(|n| FolderEdit::Create {
                id: n.id,
                name: n.name.clone(),
                parent: n.parent.and_then(|p| self.nodes.get(p)).map(|p| p.id),
            })
            .collect()
    }

    /// The folder of an entry from its group path; `None`: the root of the locker.
    pub(crate) fn folder_of(&self, path: &[Zeroizing<String>]) -> Option<Id16> {
        let mut at: Option<usize> = None;
        for group in path.iter().take(MAX_FOLDER_DEPTH) {
            match self.child(at, &folder_name(group)) {
                Some(i) => at = Some(i),
                // Merged into its parent (more than 2 048 groups).
                None => break,
            }
        }
        at.and_then(|i| self.nodes.get(i)).map(|n| n.id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn p(names: &[&str]) -> Vec<Zeroizing<String>> {
        names
            .iter()
            .map(|n| Zeroizing::new((*n).to_owned()))
            .collect()
    }

    fn counter() -> impl FnMut() -> Result<Id16, ()> {
        let mut n = 0u32;
        move || {
            n += 1;
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            Ok(id)
        }
    }

    #[test]
    fn groups_become_a_tree_shared_by_their_entries() {
        let paths = [
            p(&["Internet", "Mail"]),
            p(&[]),
            p(&["Internet"]),
            p(&["Banque"]),
        ];
        let g = GroupFolders::plan(paths.iter().map(Vec::as_slice), counter()).unwrap();
        assert_eq!(g.len(), 3);
        let edits = g.edits();
        let FolderEdit::Create { id: internet, .. } = &edits[0] else {
            panic!()
        };
        let FolderEdit::Create { parent, name, .. } = &edits[1] else {
            panic!()
        };
        assert_eq!(name.as_str(), "Mail");
        assert_eq!(parent, &Some(*internet));
        assert_eq!(g.folder_of(&p(&[])), None);
        assert_eq!(g.folder_of(&p(&["Internet"])), Some(*internet));
        assert!(g.folder_of(&p(&["Internet", "Mail"])).is_some());
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(folder_name(" A\u{7}b\n ").as_str(), "Ab");
        assert_eq!(folder_name("\t").as_str(), UNNAMED);
        let long = "é".repeat(200);
        let cut = folder_name(&long);
        assert!(cut.len() <= MAX_FOLDER_NAME && cut.chars().all(|c| c == 'é'));
        assert!(hirzla_vault::folder::is_valid_folder_name(&cut));
        assert_eq!(folder_name("Perso/Pro").as_str(), "Perso/Pro");
    }

    #[test]
    fn deep_groups_are_merged_into_their_level_32_ancestor() {
        let names: Vec<String> = (0..40).map(|i| format!("N{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let path = p(&refs);
        let g = GroupFolders::plan([path.as_slice()], counter()).unwrap();
        assert_eq!(g.len(), MAX_FOLDER_DEPTH);
        assert_eq!(g.folder_of(&path), g.folder_of(&path[..MAX_FOLDER_DEPTH]));
    }

    #[test]
    fn groups_past_the_limit_are_merged_into_their_parent() {
        let paths: Vec<Vec<Zeroizing<String>>> = (0..MAX_FOLDERS + 3)
            .map(|i| p(&["Racine", &format!("G{i}")]))
            .collect();
        let g = GroupFolders::plan(paths.iter().map(Vec::as_slice), counter()).unwrap();
        assert_eq!(g.len(), MAX_FOLDERS);
        let top = g.folder_of(&p(&["Racine"]));
        assert!(top.is_some());
        assert_eq!(g.folder_of(&paths[MAX_FOLDERS + 2]), top);
        assert_ne!(g.folder_of(&paths[0]), top);
    }
}
