//! Export and import of a locker (`docs/format.md` § 16, ADR 0077): what goes from a vault into
//! an [`ExportContent`], and how an [`ExportContent`] becomes a new locker of another vault.
//!
//! The import never reuses anything of the exporter's vault: new locker, new secret and
//! attachment identifiers, new keys, operations signed by the importing device.

use std::collections::BTreeMap;

use hirzla_crypto::util::random_array;
use zeroize::Zeroizing;

use super::{now_ms, Vault};
use crate::error::{ExportRefusal, VaultError};
use crate::export::{
    self, ExportAttachment, ExportContent, ExportLocker, ExportSecret, MAX_ATTACHMENTS, MAX_FILE,
    MAX_SECRETS,
};
use crate::model::Id16;
use crate::secret::{
    merge_locker, AttachmentRef, FieldValue, LockerBody, LockerField, SecretLink, SecretState,
    SetKind, SetValue,
};

/// Longest tag (`format.md` § 8.2): a folder path longer than this is not turned into a tag.
const MAX_TAG: usize = 128;
/// Most tags of a secret.
const MAX_TAGS: usize = 64;

/// What an export left out, in counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportStats {
    /// Active secrets exported.
    pub secrets: u64,
    /// Secrets in the trash, not exported.
    pub trashed: u64,
    /// Attachments exported.
    pub attachments: u64,
    /// Links to a secret outside the export (another locker, or a secret not exported),
    /// left out.
    pub links_dropped: u64,
}

/// What an import created, in counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Secrets created.
    pub secrets: u64,
    /// Attachments stored.
    pub attachments: u64,
    /// Secrets whose folder path became a tag (folders are not in this vault yet, ADR 0076).
    pub folders_as_tags: u64,
    /// Secrets the vault refused.
    pub refused: u64,
}

fn text(v: Option<&FieldValue>) -> Option<Zeroizing<String>> {
    match v {
        Some(FieldValue::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

impl Vault {
    /// The description of a locker, from its metadata heads.
    fn locker_meta(&self, locker: &Id16) -> Result<LockerBody, VaultError> {
        let shard = self.shard(locker)?;
        let mut heads = Vec::new();
        for h in &shard.meta_heads {
            let (_, p) = self.load(h)?;
            heads.push(LockerBody::from_value(
                p.content.as_ref().ok_or(VaultError::Corrupt)?,
            )?);
        }
        merge_locker(&heads).ok_or(VaultError::Corrupt)
    }

    /// Gathers what an export of `locker` carries: the current state of its active secrets,
    /// their attachments, links inside the export, and the locker's description.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown locker, [`VaultError::Export`] with
    /// [`ExportRefusal::TooLarge`] past the limits of the format, or a failure.
    pub fn export_locker(&self, locker: Id16) -> Result<(ExportContent, ExportStats), VaultError> {
        let too_large = VaultError::Export(ExportRefusal::TooLarge);
        let shard = self.shard(&locker)?.clone();
        let meta = self.locker_meta(&locker)?;
        let field = |f| meta.fields.get(&f).map(|e| &e.value);
        let locker_desc = ExportLocker {
            name: text(field(LockerField::Name)).ok_or(VaultError::Corrupt)?,
            description: text(field(LockerField::Description)),
            color: match field(LockerField::Color) {
                Some(FieldValue::Uint(n)) => Some(*n),
                _ => None,
            },
            icon: text(field(LockerField::Icon)).map(|i| i.as_str().to_owned()),
        };

        let mut stats = ExportStats::default();
        let mut ranks: BTreeMap<Id16, u32> = BTreeMap::new();
        for e in shard.entries.values() {
            match e.state {
                SecretState::Active => {
                    let r = u32::try_from(ranks.len()).map_err(|_| too_large)?;
                    ranks.insert(e.secret_id, r);
                }
                SecretState::Trash => stats.trashed += 1,
                SecretState::Purged => {}
            }
        }
        if ranks.len() > MAX_SECRETS {
            return Err(too_large);
        }

        let mut secrets = Vec::with_capacity(ranks.len());
        let mut attachments: Vec<ExportAttachment> = Vec::new();
        let mut attachment_ranks: BTreeMap<Id16, u32> = BTreeMap::new();
        let mut volume = 0u64;
        for secret_id in ranks.keys() {
            let body = self.read_secret(locker, *secret_id)?;
            let mut out = ExportSecret {
                secret_type: body.secret_type,
                fields: Vec::new(),
                links: Vec::new(),
                sets: Vec::new(),
                custom: Vec::new(),
                attachments: Vec::new(),
                folder: Vec::new(),
            };
            for (f, entry) in &body.fields {
                match &entry.value {
                    FieldValue::Link(l) => match ranks.get(&l.secret) {
                        Some(r) if l.locker == locker => out.links.push((*f, *r)),
                        _ => stats.links_dropped += 1,
                    },
                    v => out.fields.push((*f, v.clone())),
                }
            }
            for (k, set) in &body.sets {
                if *k == SetKind::Attachments {
                    for v in set.visible() {
                        let SetValue::Attachment(a) = v else {
                            continue;
                        };
                        let rank = match attachment_ranks.get(&a.id) {
                            Some(r) => *r,
                            None => {
                                volume = volume.saturating_add(a.size);
                                if volume > MAX_FILE as u64 || attachments.len() >= MAX_ATTACHMENTS
                                {
                                    return Err(too_large);
                                }
                                let data = self.read_attachment(locker, a)?;
                                let r = u32::try_from(attachments.len()).map_err(|_| too_large)?;
                                attachments.push(ExportAttachment {
                                    name: a.name.clone(),
                                    media_type: a.media_type.clone(),
                                    data,
                                });
                                attachment_ranks.insert(a.id, r);
                                r
                            }
                        };
                        if !out.attachments.contains(&rank) {
                            out.attachments.push(rank);
                        }
                    }
                    continue;
                }
                let mut items: Vec<Zeroizing<String>> = Vec::new();
                for v in set.visible() {
                    if let SetValue::Text(t) = v {
                        if !items.contains(t) {
                            items.push(t.clone());
                        }
                    }
                }
                if !items.is_empty() {
                    out.sets.push((*k, items));
                }
            }
            out.custom = body
                .custom
                .values()
                .filter_map(|c| c.value.clone())
                .collect();
            secrets.push(out);
        }
        stats.secrets = secrets.len() as u64;
        stats.attachments = attachments.len() as u64;
        Ok((
            ExportContent {
                created_ms: now_ms(),
                locker: locker_desc,
                secrets,
                attachments,
            },
            stats,
        ))
    }

    /// Creates a new locker from an export: the locker named `name` (or as in the file), its
    /// attachments, then its secrets, with links pointing to the new secrets. Everything is
    /// checked before the first write.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] for a bad name or content the vault refuses,
    /// [`VaultError::Export`] with [`ExportRefusal::Malformed`] for inconsistent content, or a
    /// failure. A failure after the first write leaves the new locker partly filled.
    pub fn import_locker(
        &mut self,
        content: &ExportContent,
        name: Option<&str>,
    ) -> Result<(Id16, ImportStats), VaultError> {
        let name = name.unwrap_or(&content.locker.name);
        if name.is_empty() || name.len() > 256 {
            return Err(VaultError::InvalidInput);
        }
        export::check_content(content)?;
        let mut extra = Vec::new();
        if let Some(d) = &content.locker.description {
            extra.push((LockerField::Description, FieldValue::Text(d.clone())));
        }
        if let Some(c) = content.locker.color {
            extra.push((LockerField::Color, FieldValue::Uint(c)));
        }
        if let Some(i) = &content.locker.icon {
            extra.push((LockerField::Icon, FieldValue::text(i)));
        }
        let mut ids: Vec<Id16> = Vec::with_capacity(content.secrets.len());
        for _ in &content.secrets {
            ids.push(random_array()?);
        }

        let locker: Id16 = random_array()?;
        self.create_locker_with_id(locker, name, extra, false)?;
        let mut stats = ImportStats::default();
        let mut refs: Vec<AttachmentRef> = Vec::with_capacity(content.attachments.len());
        for a in &content.attachments {
            refs.push(self.add_attachment(locker, &a.name, &a.media_type, &a.data)?);
            stats.attachments += 1;
        }
        for (secret, id) in content.secrets.iter().zip(&ids) {
            let own: Vec<AttachmentRef> = secret
                .attachments
                .iter()
                .filter_map(|r| refs.get(*r as usize).cloned())
                .collect();
            let mut edit = export::edit_for(
                secret,
                |r| SecretLink {
                    locker,
                    secret: ids.get(r as usize).copied().unwrap_or(*id),
                },
                own,
            );
            if !secret.folder.is_empty() {
                let path: Vec<&str> = secret.folder.iter().map(|n| n.as_str()).collect();
                let tag = Zeroizing::new(path.join("/"));
                let tags = edit.add.iter().filter(|(k, _)| *k == SetKind::Tags).count();
                let present = edit.add.iter().any(|(k, v)| {
                    *k == SetKind::Tags && matches!(v, SetValue::Text(t) if *t == tag)
                });
                if tag.len() <= MAX_TAG && (present || tags < MAX_TAGS) {
                    if !present {
                        edit.add.push((SetKind::Tags, SetValue::Text(tag)));
                    }
                    stats.folders_as_tags += 1;
                }
            }
            match self.write_secret(locker, *id, Some(secret.secret_type), edit, None) {
                Ok(()) => stats.secrets += 1,
                Err(VaultError::InvalidInput) => stats.refused += 1,
                Err(e) => return Err(e),
            }
        }
        Ok((locker, stats))
    }
}

#[cfg(test)]
mod tests;
