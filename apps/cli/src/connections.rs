//! SSH and RDP connections and SSH keys (local API version 6, `docs/api-locale.md` § 17,
//! ADR 0067). The command line stores and shows them; it opens no session.

use std::io::Read;
use std::path::{Path, PathBuf};

use hirzla_core::client::Client;
use hirzla_core::connections::proto::{
    ConnectionCard, ConnectionFields, ConnectionKey, ConnectionReply, ConnectionRequest, LinkState,
    ResolvedLink, MAX_PRIVATE_KEY, MAX_PUBLIC_KEY,
};
use hirzla_core::proto::{ErrorCode, ErrorReply, ListEntry, MAX_PASSWORD};
use hirzla_vault::secret::{SecretLink, SecretType};
use zeroize::Zeroizing;

use crate::args::{ConnectionCommand, ConnectionOptions, SshKeyAdd};
use crate::{client_message, hex, list, refusal_message, resolve, say, server, term, Session};

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn connection_message(code: ErrorCode) -> String {
    match code {
        ErrorCode::InvalidInput => "valeur refusée : hôte, port, identifiant, domaine ou \
             empreinte non valide, champ non permis pour ce type de connexion, clé ou rebond \
             qui n'est pas du type attendu, ou écriture non permise dans ce casier."
            .into(),
        ErrorCode::NotFound => "connexion, clé SSH ou rebond introuvable.".into(),
        code => refusal_message(&ErrorReply::new(code)),
    }
}

/// Sends one connection request; an old core answers `UnsupportedVersion`.
fn call(client: &mut Client, request: &ConnectionRequest) -> Result<ConnectionReply, String> {
    match client.call_connection(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(code)) => Err(connection_message(code)),
        Err(e) => Err(client_message(&e)),
    }
}

/// The active secret of type `wanted` with that exact title (case-insensitive).
fn link_by_title(
    c: &mut Client,
    title: &str,
    wanted: SecretType,
    what: &str,
) -> Result<SecretLink, String> {
    let hits: Vec<ListEntry> = list(c, Some(title), false)?
        .into_iter()
        .filter(|e| {
            e.secret_type == wanted as u64
                && e.title
                    .chars()
                    .flat_map(char::to_lowercase)
                    .eq(title.chars().flat_map(char::to_lowercase))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(SecretLink {
            locker: one.locker,
            secret: one.id,
        }),
        [] => Err(format!("{what} introuvable : {title}.")),
        _ => Err(format!(
            "plusieurs secrets « {title} » correspondent : renommez-en un."
        )),
    }
}

/// The fields the options set. The password is asked here, after every other check.
fn fields_of(c: &mut Client, o: &ConnectionOptions) -> Result<ConnectionFields, String> {
    let ssh_key = o
        .key
        .as_deref()
        .map(|k| link_by_title(c, k, SecretType::SshKey, "clé SSH"))
        .transpose()?;
    let jump = o
        .jump
        .as_deref()
        .map(|j| link_by_title(c, j, SecretType::SshConnection, "connexion SSH de rebond"))
        .transpose()?;
    let password = if o.password {
        Some(term::read_secret(
            "Mot de passe de la connexion : ",
            true,
            MAX_PASSWORD,
        )?)
    } else {
        None
    };
    Ok(ConnectionFields {
        host: o.host.as_deref().map(z),
        port: o.port,
        username: o.username.as_deref().map(z),
        domain: o.domain.as_deref().map(z),
        password,
        ssh_key,
        jump,
        host_key: o.host_key.as_deref().map(z),
        ..ConnectionFields::default()
    })
}

fn clear_key(name: &str) -> Result<ConnectionKey, String> {
    match name {
        "port" => Ok(ConnectionKey::Port),
        "identifiant" => Ok(ConnectionKey::Username),
        "domaine" => Ok(ConnectionKey::Domain),
        "mot-de-passe" => Ok(ConnectionKey::Password),
        "cle" => Ok(ConnectionKey::SshKey),
        "rebond" => Ok(ConnectionKey::Jump),
        "empreinte" => Ok(ConnectionKey::HostKey),
        "notes" => Ok(ConnectionKey::Notes),
        _ => Err(format!(
            "--effacer {name} : champ inconnu. Champs : port, identifiant, domaine, \
             mot-de-passe, cle, rebond, empreinte, notes."
        )),
    }
}

/// The connection meant by a name or an identifier prefix.
fn resolve_connection(
    c: &mut Client,
    name: Option<&str>,
    id: Option<&str>,
) -> Result<ListEntry, String> {
    let entry = resolve(c, name, id)?;
    if entry.secret_type != SecretType::SshConnection as u64
        && entry.secret_type != SecretType::RdpConnection as u64
    {
        return Err("ce secret n'est pas une connexion.".into());
    }
    Ok(entry)
}

/// Whether `s` can be shown in a command without quoting.
fn shell_safe(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// `[user@]host[:port]` of a jump host, as `ssh -J` reads it.
fn jump_spec(j: &ResolvedLink) -> Option<String> {
    let host = j.host.as_ref()?;
    if !shell_safe(host) {
        return None;
    }
    let mut out = String::new();
    if let Some(u) = &j.username {
        if !shell_safe(u) || u.contains(':') {
            return None;
        }
        out.push_str(u);
        out.push('@');
    }
    // An IPv6 address takes brackets before a port.
    if host.contains(':') {
        out.push('[');
        out.push_str(host);
        out.push(']');
    } else {
        out.push_str(host);
    }
    match j.port {
        Some(22) | None => {}
        Some(p) => out.push_str(&format!(":{p}")),
    }
    Some(out)
}

/// The `ssh` command of an SSH connection whose every jump host is valid; `None` for an RDP
/// connection, a broken chain, or a value that would need quoting.
fn ssh_command(card: &ConnectionCard) -> Option<String> {
    if card.secret_type != SecretType::SshConnection {
        return None;
    }
    let host = card.fields.host.as_ref()?;
    if !shell_safe(host) || card.jumps.iter().any(|j| j.state != LinkState::Valid) {
        return None;
    }
    let mut out = String::from("ssh");
    if card.effective_port != 22 {
        out.push_str(&format!(" -p {}", card.effective_port));
    }
    if !card.jumps.is_empty() {
        // The card lists the nearest jump host first; `ssh -J` wants the first hop first.
        let specs = card
            .jumps
            .iter()
            .rev()
            .map(jump_spec)
            .collect::<Option<Vec<String>>>()?;
        out.push_str(" -J ");
        out.push_str(&specs.join(","));
    }
    out.push(' ');
    if let Some(u) = &card.fields.username {
        if !shell_safe(u) || u.contains(':') {
            return None;
        }
        out.push_str(u);
        out.push('@');
    }
    out.push_str(host);
    Some(out)
}

fn link_line(l: &ResolvedLink) -> String {
    let title = l.title.as_ref().map_or("", |t| t.as_str());
    match l.state {
        LinkState::Valid => title.to_owned(),
        LinkState::Trashed => format!("{title} (à la corbeille)"),
        LinkState::Broken => format!(
            "lien rompu ({}) : secret supprimé, ou casier absent de ce poste",
            hex(&l.link.secret[..4])
        ),
        LinkState::WrongType => format!(
            "lien rompu ({}) : le secret n'est pas du type attendu",
            hex(&l.link.secret[..4])
        ),
        LinkState::Loop => "chaîne de rebonds rompue : boucle, ou plus de 8 rebonds".to_owned(),
    }
}

/// The lines of a card. No password, no notes: they are not in it.
fn card_lines(card: &ConnectionCard) -> Vec<String> {
    let text = |t: &Option<Zeroizing<String>>| t.as_ref().map_or("", |t| t.as_str()).to_owned();
    let mut lines = Vec::new();
    let mut line = |label: &str, value: String| lines.push(format!("{label:<22}{value}"));
    line(
        "Type :",
        if card.secret_type == SecretType::RdpConnection {
            "connexion RDP"
        } else {
            "connexion SSH"
        }
        .to_owned(),
    );
    line(
        "Titre :",
        format!(
            "{}{}",
            text(&card.fields.title),
            if card.trashed { " (corbeille)" } else { "" }
        ),
    );
    line(
        "Hôte :",
        format!(
            "{}  port {}{}",
            text(&card.fields.host),
            card.effective_port,
            if card.fields.port.is_none() {
                " (par défaut)"
            } else {
                ""
            }
        ),
    );
    if card.fields.domain.is_some() {
        line("Domaine :", text(&card.fields.domain));
    }
    if card.fields.username.is_some() {
        line("Identifiant :", text(&card.fields.username));
    }
    line(
        "Mot de passe :",
        if card.has_password {
            "enregistré (« hirzla get » pour le copier)"
        } else {
            "aucun"
        }
        .to_owned(),
    );
    if let Some(k) = &card.ssh_key {
        line("Clé SSH :", link_line(k));
        if let Some(p) = &k.public_key {
            line("Clé publique :", p.as_str().to_owned());
        }
    }
    for (i, j) in card.jumps.iter().enumerate() {
        let label = if i == 0 { "Rebond :" } else { "  puis par :" };
        let mut value = link_line(j);
        if let (true, Some(h), Some(p)) = (j.state.has_details(), &j.host, j.port) {
            value.push_str(&format!("  ({}, port {p})", h.as_str()));
        }
        line(label, value);
    }
    if card.fields.host_key.is_some() {
        line("Empreinte de l'hôte :", text(&card.fields.host_key));
    }
    if card.has_notes {
        line(
            "Notes :",
            "enregistrées (« hirzla get --champ notes »)".to_owned(),
        );
    }
    if !card.tags.is_empty() {
        let tags: Vec<&str> = card.tags.iter().map(|t| t.as_str()).collect();
        line("Étiquettes :", tags.join(", "));
    }
    if let Some(command) = ssh_command(card) {
        line("Commande :", command);
    }
    lines
}

/// `connexion ssh|rdp|voir|modifier`.
pub fn run(session: &Session<'_>, command: &ConnectionCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    match command {
        ConnectionCommand::Create {
            rdp,
            name,
            options,
            locker,
            tags,
        } => {
            let locker = locker
                .as_deref()
                .map(|l| server::resolve_locker(&mut c, l))
                .transpose()?;
            let mut fields = fields_of(&mut c, options)?;
            fields.title = Some(z(name));
            let ConnectionReply::Created { id, .. } = call(
                &mut c,
                &ConnectionRequest::Create {
                    locker,
                    secret_type: if *rdp {
                        SecretType::RdpConnection
                    } else {
                        SecretType::SshConnection
                    },
                    fields,
                    tags: tags.iter().map(|t| z(t)).collect(),
                },
            )?
            else {
                return Err(unexpected());
            };
            say(&format!("Connexion créée ({}).", hex(&id[..4])));
            Ok(())
        }
        ConnectionCommand::Show { name, id } => {
            let entry = resolve_connection(&mut c, name.as_deref(), id.as_deref())?;
            let ConnectionReply::Card(card) = call(
                &mut c,
                &ConnectionRequest::Read {
                    locker: entry.locker,
                    id: entry.id,
                },
            )?
            else {
                return Err(unexpected());
            };
            for l in card_lines(&card) {
                say(&l);
            }
            Ok(())
        }
        ConnectionCommand::Update {
            name,
            id,
            options,
            title,
            clear,
        } => {
            let clear = clear
                .iter()
                .map(|k| clear_key(k))
                .collect::<Result<Vec<_>, _>>()?;
            let entry = resolve_connection(&mut c, name.as_deref(), id.as_deref())?;
            let mut set = fields_of(&mut c, options)?;
            set.title = title.as_deref().map(z);
            call(
                &mut c,
                &ConnectionRequest::Update {
                    locker: entry.locker,
                    id: entry.id,
                    set,
                    clear,
                },
            )?;
            say("Connexion modifiée.");
            Ok(())
        }
    }
}

/// Reads at most `max` bytes of a file into an erasing buffer reserved in advance.
fn read_bounded(path: &Path, max: usize, what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let f =
        std::fs::File::open(path).map_err(|_| format!("impossible de lire {}.", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(max + 1));
    f.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("impossible de lire {}.", path.display()))?;
    if bytes.len() > max {
        return Err(format!("{} : {what} trop grande.", path.display()));
    }
    Ok(bytes)
}

/// The first line of a public key file (`ssh-ed25519 AAAA… comment`).
fn first_line(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let line = bytes.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(z(line))
    }
}

/// `FICHIER.pub`, next to the private key.
fn default_public(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// `cle-ssh ajouter NOM FICHIER`.
pub fn add_ssh_key(session: &Session<'_>, a: &SshKeyAdd) -> Result<(), String> {
    let private_key = read_bounded(&a.file, MAX_PRIVATE_KEY, "clé privée")?;
    let public = match &a.public {
        Some(p) => Some(p.clone()),
        None => Some(default_public(&a.file)).filter(|p| p.is_file()),
    };
    let public_key = match public {
        Some(p) => Some(
            first_line(&read_bounded(&p, MAX_PUBLIC_KEY, "clé publique")?)
                .ok_or_else(|| format!("{} n'est pas une clé publique.", p.display()))?,
        ),
        None => None,
    };
    let mut c = session.connect(false)?;
    let locker = a
        .locker
        .as_deref()
        .map(|l| server::resolve_locker(&mut c, l))
        .transpose()?;
    let passphrase = if a.passphrase {
        Some(term::read_secret(
            "Phrase de passe de la clé : ",
            false,
            MAX_PASSWORD,
        )?)
    } else {
        None
    };
    let had_public = public_key.is_some();
    let ConnectionReply::Created { id, .. } = call(
        &mut c,
        &ConnectionRequest::SshKeyCreate {
            locker,
            title: z(&a.name),
            private_key,
            public_key,
            passphrase,
            username: a.username.as_deref().map(z),
            tags: a.tags.iter().map(|t| z(t)).collect(),
        },
    )
    .map_err(|e| {
        if e.starts_with("valeur refusée") {
            "clé refusée : le fichier doit être une clé privée au format OpenSSH \
             (« -----BEGIN OPENSSH PRIVATE KEY----- »)."
                .to_owned()
        } else {
            e
        }
    })?
    else {
        return Err(unexpected());
    };
    say(&format!(
        "Clé SSH rangée ({}){}. Le fichier d'origine n'a pas été modifié.",
        hex(&id[..4]),
        if had_public {
            ", avec sa clé publique"
        } else {
            ", sans clé publique"
        }
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn link(n: u8) -> SecretLink {
        SecretLink {
            locker: [n; 16],
            secret: [n; 16],
        }
    }

    fn jump(title: &str, host: &str, port: u16, user: Option<&str>) -> ResolvedLink {
        ResolvedLink {
            link: link(1),
            state: LinkState::Valid,
            title: Some(z(title)),
            host: Some(z(host)),
            port: Some(port),
            username: user.map(z),
            public_key: None,
        }
    }

    fn card(host: &str, port: Option<u16>, user: Option<&str>) -> ConnectionCard {
        ConnectionCard {
            secret_type: SecretType::SshConnection,
            trashed: false,
            fields: ConnectionFields {
                title: Some(z("Serveur web")),
                host: Some(z(host)),
                port,
                username: user.map(z),
                ..ConnectionFields::default()
            },
            has_password: true,
            has_notes: false,
            tags: Vec::new(),
            effective_port: port.unwrap_or(22),
            ssh_key: None,
            jumps: Vec::new(),
        }
    }

    #[test]
    fn the_ssh_command_follows_the_jump_chain() {
        assert_eq!(
            ssh_command(&card("web-01.exemple.test", None, Some("admin"))).unwrap(),
            "ssh admin@web-01.exemple.test"
        );
        assert_eq!(
            ssh_command(&card("web-01", Some(2200), None)).unwrap(),
            "ssh -p 2200 web-01"
        );
        // Nearest jump host first in the card, first hop first for `ssh -J`.
        let mut c = card("web-01", None, Some("admin"));
        c.jumps = vec![
            jump("Bastion interne", "10.0.0.1", 22, None),
            jump("Bastion Hornn", "2001:db8::1", 2222, Some("max")),
        ];
        assert_eq!(
            ssh_command(&c).unwrap(),
            "ssh -J max@[2001:db8::1]:2222,10.0.0.1 admin@web-01"
        );
    }

    #[test]
    fn no_ssh_command_for_rdp_a_broken_chain_or_a_value_to_quote() {
        let mut rdp = card("poste", None, None);
        rdp.secret_type = SecretType::RdpConnection;
        assert!(ssh_command(&rdp).is_none());

        let mut broken = card("web-01", None, None);
        broken.jumps = vec![ResolvedLink::bare(link(2), LinkState::Broken)];
        assert!(ssh_command(&broken).is_none());
        broken.jumps = vec![jump("Bastion", "b", 22, None)];
        broken.jumps[0].state = LinkState::Trashed;
        assert!(ssh_command(&broken).is_none());

        // A user name with a space or a shell character is never pasted into a command.
        assert!(ssh_command(&card("web-01", None, Some("Max Dupont"))).is_none());
        assert!(ssh_command(&card("web-01", None, Some("a;b"))).is_none());
        let mut c = card("web-01", None, None);
        c.jumps = vec![jump("Bastion", "b", 22, Some("$(x)"))];
        assert!(ssh_command(&c).is_none());
    }

    #[test]
    fn the_card_shows_no_secret_and_names_broken_links() {
        let mut c = card("web-01.exemple.test", None, Some("admin"));
        c.ssh_key = Some(ResolvedLink::bare(link(0xab), LinkState::Broken));
        c.jumps = vec![
            jump("Bastion Hornn", "bastion.exemple.test", 2222, Some("max")),
            ResolvedLink::bare(link(3), LinkState::Loop),
        ];
        c.fields.host_key = Some(z("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        let lines = card_lines(&c).join("\n");
        assert!(lines.contains("connexion SSH"));
        assert!(lines.contains("web-01.exemple.test  port 22 (par défaut)"));
        assert!(lines.contains("lien rompu (abababab)"));
        assert!(lines.contains("Bastion Hornn  (bastion.exemple.test, port 2222)"));
        assert!(lines.contains("chaîne de rebonds rompue"));
        assert!(lines.contains("SHA256:"));
        assert!(lines.contains("Mot de passe :        enregistré"));
        // A broken chain: no command.
        assert!(!lines.contains("Commande"));
    }

    #[test]
    fn clearable_fields_have_a_name() {
        for name in [
            "port",
            "identifiant",
            "domaine",
            "mot-de-passe",
            "cle",
            "rebond",
            "empreinte",
            "notes",
        ] {
            assert!(clear_key(name).unwrap().clearable());
        }
        assert!(clear_key("titre").is_err());
        assert!(clear_key("hote").is_err());
    }

    #[test]
    fn public_key_files() {
        assert_eq!(
            first_line(b"ssh-ed25519 AAAA deploy\r\nautre\n")
                .unwrap()
                .as_str(),
            "ssh-ed25519 AAAA deploy"
        );
        assert!(first_line(b"\n").is_none());
        assert!(first_line(&[0xff, 0xfe]).is_none());
        assert_eq!(
            default_public(Path::new("/k/id_ed25519")),
            PathBuf::from("/k/id_ed25519.pub")
        );
    }

    #[test]
    fn bounded_reads_refuse_a_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cle");
        std::fs::write(&path, vec![b'a'; 33]).unwrap();
        assert!(read_bounded(&path, 32, "clé privée").is_err());
        assert_eq!(read_bounded(&path, 33, "clé privée").unwrap().len(), 33);
        assert!(read_bounded(&dir.path().join("absent"), 32, "clé privée").is_err());
    }

    #[test]
    fn messages_are_never_empty() {
        for c in [
            ErrorCode::InvalidInput,
            ErrorCode::NotFound,
            ErrorCode::Locked,
            ErrorCode::UnsupportedVersion,
        ] {
            assert!(!connection_message(c).is_empty());
        }
    }
}
