//! SSH and RDP connections, and the import of an existing SSH key (`docs/api-locale.md` § 17,
//! local API version 6, ADR 0067).
//!
//! The application stores and shows a connection; it opens no session and starts no client.
//! The password and the notes are write-only here: they are read like any other secret
//! field, through `reveal_field` and `copy_field`. A private key is read from the file the
//! user chose with the system's file picker, sent to the core, and readable by nothing after.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use hirzla_core::connections::proto::{
    ConnectionCard, ConnectionFields, ConnectionKey, ConnectionReply, ConnectionRequest, LinkState,
    ResolvedLink, MAX_PRIVATE_KEY, MAX_PUBLIC_KEY,
};
use hirzla_core::proto::{ErrorCode, ErrorReply, MAX_ITEMS, MAX_TEXT};
use hirzla_vault::secret::{SecretLink, SecretType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{guard, hex, id16, on_main_thread, AppState, SecretRef, State};
use crate::error::DesktopError;

const REFUSED: &str = "Valeur refusée : vérifiez l'hôte, le port, l'identifiant, l'empreinte \
                       (« SHA256:… »), la clé ou le rebond choisis, et vos droits sur ce casier.";

/// Kind of connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    /// SSH.
    Ssh,
    /// RDP.
    Rdp,
}

fn link(target: &SecretRef) -> Result<SecretLink, DesktopError> {
    Ok(SecretLink {
        locker: id16(&target.locker)?,
        secret: id16(&target.id)?,
    })
}

fn text(value: Zeroizing<String>) -> Result<Zeroizing<String>, DesktopError> {
    if value.is_empty() || value.len() > MAX_TEXT {
        return Err(DesktopError::Invalid("Valeur vide ou trop longue."));
    }
    Ok(value)
}

fn tags(items: Vec<Zeroizing<String>>) -> Result<Vec<Zeroizing<String>>, DesktopError> {
    if items.len() > MAX_ITEMS {
        return Err(DesktopError::Invalid("Trop d'étiquettes."));
    }
    items.into_iter().map(text).collect()
}

/// The fields of a connection as the interface sends them: every one optional. An absent
/// field is left alone; an empty text is refused (clearing is asked with `clear`).
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldsDto {
    #[serde(default)]
    title: Option<Zeroizing<String>>,
    #[serde(default)]
    host: Option<Zeroizing<String>>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<Zeroizing<String>>,
    #[serde(default)]
    domain: Option<Zeroizing<String>>,
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    ssh_key: Option<SecretRef>,
    #[serde(default)]
    jump: Option<SecretRef>,
    #[serde(default)]
    host_key: Option<Zeroizing<String>>,
    #[serde(default)]
    notes: Option<Zeroizing<String>>,
    #[serde(default)]
    favorite: Option<bool>,
}

impl std::fmt::Debug for FieldsDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FieldsDto")
    }
}

impl FieldsDto {
    fn into_fields(self) -> Result<ConnectionFields, DesktopError> {
        Ok(ConnectionFields {
            title: self.title.map(text).transpose()?,
            host: self.host.map(text).transpose()?,
            port: self.port,
            username: self.username.map(text).transpose()?,
            domain: self.domain.map(text).transpose()?,
            password: self.password.map(text).transpose()?,
            ssh_key: self.ssh_key.as_ref().map(link).transpose()?,
            jump: self.jump.as_ref().map(link).transpose()?,
            host_key: self.host_key.map(text).transpose()?,
            notes: self.notes.map(text).transpose()?,
            favorite: self.favorite,
        })
    }
}

/// A new connection.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewConnection {
    kind: ConnectionKind,
    /// Locker; `None` for the personal one.
    locker: Option<String>,
    fields: FieldsDto,
    #[serde(default)]
    tags: Vec<Zeroizing<String>>,
}

impl NewConnection {
    fn into_request(self) -> Result<ConnectionRequest, DesktopError> {
        let fields = self.fields.into_fields()?;
        if fields.title.is_none() || fields.host.is_none() {
            return Err(DesktopError::Invalid(
                "Le titre et l'hôte sont obligatoires.",
            ));
        }
        if self.kind == ConnectionKind::Rdp && fields.ssh_key.is_some() {
            return Err(DesktopError::Invalid(
                "Une clé SSH ne s'attache qu'à une connexion SSH.",
            ));
        }
        if self.kind == ConnectionKind::Ssh && fields.domain.is_some() {
            return Err(DesktopError::Invalid(
                "Le domaine ne concerne que les connexions RDP.",
            ));
        }
        Ok(ConnectionRequest::Create {
            locker: self.locker.as_deref().map(id16).transpose()?,
            secret_type: match self.kind {
                ConnectionKind::Ssh => SecretType::SshConnection,
                ConnectionKind::Rdp => SecretType::RdpConnection,
            },
            fields,
            tags: tags(self.tags)?,
        })
    }
}

/// Fields the interface may clear (`docs/api-locale.md` § 17.2: keys 3 to 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Clearable {
    /// Back to the default port.
    Port,
    /// User name.
    Username,
    /// Domain.
    Domain,
    /// Password.
    Password,
    /// Link to an SSH key.
    SshKey,
    /// Link to a jump host.
    Jump,
    /// Host key fingerprint.
    HostKey,
    /// Notes.
    Notes,
}

impl Clearable {
    fn key(self) -> ConnectionKey {
        match self {
            Clearable::Port => ConnectionKey::Port,
            Clearable::Username => ConnectionKey::Username,
            Clearable::Domain => ConnectionKey::Domain,
            Clearable::Password => ConnectionKey::Password,
            Clearable::SshKey => ConnectionKey::SshKey,
            Clearable::Jump => ConnectionKey::Jump,
            Clearable::HostKey => ConnectionKey::HostKey,
            Clearable::Notes => ConnectionKey::Notes,
        }
    }
}

/// A resolved link, for display.
#[derive(Clone, Serialize)]
pub struct LinkDto {
    locker: String,
    id: String,
    /// `valid`, `broken`, `trashed`, `wrong_type` or `loop`.
    state: &'static str,
    title: Option<Zeroizing<String>>,
    host: Option<Zeroizing<String>>,
    port: Option<u16>,
    username: Option<Zeroizing<String>>,
    public_key: Option<Zeroizing<String>>,
}

impl From<ResolvedLink> for LinkDto {
    fn from(l: ResolvedLink) -> Self {
        LinkDto {
            locker: hex(&l.link.locker),
            id: hex(&l.link.secret),
            state: match l.state {
                LinkState::Valid => "valid",
                LinkState::Broken => "broken",
                LinkState::Trashed => "trashed",
                LinkState::WrongType => "wrong_type",
                LinkState::Loop => "loop",
            },
            title: l.title,
            host: l.host,
            port: l.port,
            username: l.username,
            public_key: l.public_key,
        }
    }
}

/// The card of a connection: everything but the password and the notes.
#[derive(Clone, Serialize)]
pub struct CardDto {
    /// `ssh` or `rdp`.
    kind: &'static str,
    trashed: bool,
    title: Option<Zeroizing<String>>,
    host: Option<Zeroizing<String>>,
    /// Port set on the connection; `None` for the default.
    port: Option<u16>,
    effective_port: u16,
    username: Option<Zeroizing<String>>,
    domain: Option<Zeroizing<String>>,
    host_key: Option<Zeroizing<String>>,
    favorite: bool,
    has_password: bool,
    has_notes: bool,
    tags: Vec<Zeroizing<String>>,
    ssh_key: Option<LinkDto>,
    /// Jump hosts, the nearest first.
    jumps: Vec<LinkDto>,
}

impl From<ConnectionCard> for CardDto {
    fn from(c: ConnectionCard) -> Self {
        CardDto {
            kind: if c.secret_type == SecretType::RdpConnection {
                "rdp"
            } else {
                "ssh"
            },
            trashed: c.trashed,
            title: c.fields.title,
            host: c.fields.host,
            port: c.fields.port,
            effective_port: c.effective_port,
            username: c.fields.username,
            domain: c.fields.domain,
            host_key: c.fields.host_key,
            favorite: c.fields.favorite.unwrap_or(false),
            has_password: c.has_password,
            has_notes: c.has_notes,
            tags: c.tags,
            ssh_key: c.ssh_key.map(LinkDto::from),
            jumps: c.jumps.into_iter().map(LinkDto::from).collect(),
        }
    }
}

/// An SSH key to store, read from the file chosen with [`choose_ssh_key_file`].
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewSshKey {
    /// Locker; `None` for the personal one.
    locker: Option<String>,
    title: Zeroizing<String>,
    #[serde(default)]
    passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    username: Option<Zeroizing<String>>,
    #[serde(default)]
    tags: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for NewSshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewSshKey")
    }
}

/// Reads a private key file: at most [`MAX_PRIVATE_KEY`] bytes, never more even if the file
/// grows meanwhile.
fn read_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, DesktopError> {
    let unreadable = DesktopError::Import("Le fichier de la clé ne peut pas être lu.");
    let too_large = DesktopError::Import("Fichier refusé : une clé privée fait moins de 64 Kio.");
    let file = std::fs::File::open(path).map_err(|_| unreadable.clone())?;
    let limit = u64::try_from(MAX_PRIVATE_KEY).map_err(|_| unreadable.clone())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PRIVATE_KEY.saturating_add(1)));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable)?;
    if bytes.is_empty() || bytes.len() > MAX_PRIVATE_KEY {
        return Err(too_large);
    }
    Ok(bytes)
}

/// The public key written by OpenSSH next to the private one (`FILE.pub`): its first line, when
/// the file is there and readable. A public key is not required, so anything else is `None`.
fn sibling_public_key(private: &Path) -> Option<Zeroizing<String>> {
    let mut name = private.as_os_str().to_owned();
    name.push(".pub");
    let file = std::fs::File::open(PathBuf::from(name)).ok()?;
    let limit = u64::try_from(MAX_PUBLIC_KEY).ok()?;
    let mut bytes = Vec::with_capacity(1024);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_PUBLIC_KEY {
        return None;
    }
    let line = bytes.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(Zeroizing::new(line.to_owned()))
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl AppState {
    fn connection(&self, request: &ConnectionRequest) -> Result<ConnectionReply, DesktopError> {
        self.with_link(|l| l.call_connection(request))
    }

    /// Creates a connection.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_connection(&self, new: NewConnection) -> Result<SecretRef, DesktopError> {
        match self.connection(&new.into_request()?)? {
            ConnectionReply::Created { locker, id } => Ok(SecretRef {
                locker: hex(&locker),
                id: hex(&id),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Reads the card of a connection.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn connection_card(&self, target: &SecretRef) -> Result<CardDto, DesktopError> {
        match self.connection(&ConnectionRequest::Read {
            locker: id16(&target.locker)?,
            id: id16(&target.id)?,
        })? {
            ConnectionReply::Card(card) => Ok(CardDto::from(*card)),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Changes a connection: sets the fields of `set`, clears those of `clear`.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn update_connection(
        &self,
        target: &SecretRef,
        set: FieldsDto,
        clear: &[Clearable],
    ) -> Result<(), DesktopError> {
        let set = set.into_fields()?;
        if set.is_empty() && clear.is_empty() {
            return Ok(());
        }
        self.connection(&ConnectionRequest::Update {
            locker: id16(&target.locker)?,
            id: id16(&target.id)?,
            set,
            clear: clear.iter().map(|c| c.key()).collect(),
        })
        .map(drop)
    }

    /// Stores the SSH key of the file at `path`.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_ssh_key(&self, path: &Path, new: NewSshKey) -> Result<SecretRef, DesktopError> {
        let request = ConnectionRequest::SshKeyCreate {
            locker: new.locker.as_deref().map(id16).transpose()?,
            title: text(new.title)?,
            private_key: read_private_key(path)?,
            public_key: sibling_public_key(path),
            passphrase: new.passphrase.map(text).transpose()?,
            username: new.username.map(text).transpose()?,
            tags: tags(new.tags)?,
        };
        match self.connection(&request)? {
            ConnectionReply::Created { locker, id } => Ok(SecretRef {
                locker: hex(&locker),
                id: hex(&id),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }
}

/// A refusal of a connection request: the general codes only (§ 17.5).
#[must_use]
pub fn refusal(code: ErrorCode) -> DesktopError {
    if code == ErrorCode::InvalidInput {
        DesktopError::Invalid(REFUSED)
    } else {
        DesktopError::Refused(ErrorReply {
            code,
            retry_after_s: None,
            versions: Vec::new(),
        })
    }
}

/// See [`AppState::create_connection`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_connection(
    state: State<'_>,
    connection: NewConnection,
) -> Result<SecretRef, DesktopError> {
    state.create_connection(connection)
}

/// See [`AppState::connection_card`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn connection_card(state: State<'_>, target: SecretRef) -> Result<CardDto, DesktopError> {
    state.connection_card(&target)
}

/// See [`AppState::update_connection`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn update_connection(
    state: State<'_>,
    target: SecretRef,
    set: FieldsDto,
    clear: Vec<Clearable>,
) -> Result<(), DesktopError> {
    state.update_connection(&target, set, &clear)
}

/// Asks for a private key file with the system's file picker, opened by this process; the
/// web view only learns the file's name.
#[tauri::command(async, rename_all = "snake_case")]
pub fn choose_ssh_key_file(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<String, DesktopError> {
    let path: PathBuf = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Choisir une clé privée SSH")
            .set_parent(parent)
            .pick_file()
    })?;
    let name = file_name(&path);
    *guard(&state.pending_ssh_key) = Some(path);
    Ok(name)
}

/// Stores the key chosen by [`choose_ssh_key_file`]. See [`AppState::create_ssh_key`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_ssh_key(state: State<'_>, key: NewSshKey) -> Result<SecretRef, DesktopError> {
    let path = guard(&state.pending_ssh_key)
        .clone()
        .ok_or(DesktopError::Invalid(
            "Choisissez d'abord le fichier de la clé.",
        ))?;
    let created = state.create_ssh_key(&path, key)?;
    *guard(&state.pending_ssh_key) = None;
    Ok(created)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const LOCKER: &str = "000102030405060708090a0b0c0d0e0f";
    const SECRET: &str = "101112131415161718191a1b1c1d1e1f";

    fn new(json: &str) -> Result<ConnectionRequest, DesktopError> {
        serde_json::from_str::<NewConnection>(json)
            .unwrap()
            .into_request()
    }

    #[test]
    fn a_connection_needs_a_title_and_a_host() {
        assert!(new(
            r#"{"kind":"ssh","locker":null,"fields":{"title":"NAS","host":"nas.example"}}"#
        )
        .is_ok());
        for json in [
            r#"{"kind":"ssh","locker":null,"fields":{"host":"nas.example"}}"#,
            r#"{"kind":"ssh","locker":null,"fields":{"title":"NAS"}}"#,
            r#"{"kind":"ssh","locker":null,"fields":{"title":"NAS","host":""}}"#,
        ] {
            assert!(matches!(new(json), Err(DesktopError::Invalid(_))), "{json}");
        }
    }

    #[test]
    fn fields_of_the_other_kind_are_refused() {
        let key = format!(r#"{{"locker":"{LOCKER}","id":"{SECRET}"}}"#);
        let rdp_with_key = format!(
            r#"{{"kind":"rdp","locker":null,"fields":{{"title":"TS","host":"ts.example","ssh_key":{key}}}}}"#
        );
        assert!(matches!(new(&rdp_with_key), Err(DesktopError::Invalid(_))));
        let ssh_with_domain = r#"{"kind":"ssh","locker":null,"fields":{"title":"NAS","host":"nas.example","domain":"CORP"}}"#;
        assert!(matches!(
            new(ssh_with_domain),
            Err(DesktopError::Invalid(_))
        ));
        // A jump host is allowed for both.
        let rdp_with_jump = format!(
            r#"{{"kind":"rdp","locker":null,"fields":{{"title":"TS","host":"ts.example","jump":{key}}}}}"#
        );
        assert!(new(&rdp_with_jump).is_ok());
    }

    #[test]
    fn unknown_fields_kinds_and_bad_links_are_refused() {
        assert!(serde_json::from_str::<NewConnection>(
            r#"{"kind":"vnc","locker":null,"fields":{"title":"x","host":"h"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<NewConnection>(
            r#"{"kind":"ssh","locker":null,"fields":{"title":"x","host":"h","private_key":"k"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Vec<Clearable>>(r#"["title"]"#).is_err());
        assert!(serde_json::from_str::<Vec<Clearable>>(r#"["host"]"#).is_err());
        let bad_link = r#"{"kind":"ssh","locker":null,"fields":{"title":"x","host":"h","jump":{"locker":"zz","id":"zz"}}}"#;
        assert!(matches!(new(bad_link), Err(DesktopError::Invalid(_))));
    }

    #[test]
    fn a_private_key_file_is_bounded() {
        let dir = std::env::temp_dir().join(format!("hirzla-desktop-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok");
        std::fs::write(&ok, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        assert!(read_private_key(&ok).is_ok());
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(matches!(
            read_private_key(&empty),
            Err(DesktopError::Import(_))
        ));
        let large = dir.join("large");
        std::fs::write(&large, vec![b'a'; MAX_PRIVATE_KEY + 1]).unwrap();
        assert!(matches!(
            read_private_key(&large),
            Err(DesktopError::Import(_))
        ));
        assert!(matches!(
            read_private_key(&dir.join("missing")),
            Err(DesktopError::Import(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_public_key_next_to_the_private_one_is_picked_up() {
        let dir = std::env::temp_dir().join(format!("hirzla-desktop-pub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("id_ed25519");
        assert!(sibling_public_key(&key).is_none());
        std::fs::write(
            dir.join("id_ed25519.pub"),
            b"ssh-ed25519 AAAA me@host\nrest\n",
        )
        .unwrap();
        assert_eq!(
            sibling_public_key(&key).unwrap().as_str(),
            "ssh-ed25519 AAAA me@host"
        );
        std::fs::write(dir.join("id_ed25519.pub"), b"\n").unwrap();
        assert!(sibling_public_key(&key).is_none());
        std::fs::write(dir.join("id_ed25519.pub"), vec![b'a'; MAX_PUBLIC_KEY + 1]).unwrap();
        assert!(sibling_public_key(&key).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_invalid_input_refusal_names_what_to_check() {
        assert!(matches!(
            refusal(ErrorCode::InvalidInput),
            DesktopError::Invalid(_)
        ));
        assert!(matches!(
            refusal(ErrorCode::Locked),
            DesktopError::Refused(_)
        ));
    }
}
