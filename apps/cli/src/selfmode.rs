//! Commands of the Self mode (local API version 5, `docs/api-locale.md` § 16): KeePass
//! import, version history, password change, settings, recovery kit.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hirzla_core::client::Client;
use hirzla_core::proto::{ApiValue, ErrorReply, MAX_PASSWORD};
use hirzla_core::selfmode::proto::{
    ImportReport, SelfCode, SelfReply, SelfRequest, SettingsArgs, VersionInfo,
};
use hirzla_vault::MAX_SHARE_FILE;
use zeroize::Zeroizing;

use crate::{
    client_message, field_by_name, hex, refusal_message, resolve, resolve_in, say, term, Session,
};

/// Shortest master password accepted by the command line for a new password.
const MIN_NEW_PASSWORD: usize = 12;

fn self_message(code: SelfCode, retry_after_s: Option<u64>) -> String {
    match code {
        SelfCode::General(code) => refusal_message(&ErrorReply {
            code,
            retry_after_s,
            versions: Vec::new(),
        }),
        SelfCode::ImportUnsupported => "base KeePass non prise en charge : seules les bases \
             KDBX 4 (Argon2d ou Argon2id, AES-256 ou ChaCha20) protégées par un mot de passe \
             seul sont importées."
            .into(),
        SelfCode::ImportKeyRejected => {
            "mot de passe de la base KeePass incorrect, ou base altérée.".into()
        }
        SelfCode::ImportMalformed => "fichier refusé : ce n'est pas une base KeePass lisible, \
             ou elle est altérée ou trop grande."
            .into(),
    }
}

/// Sends one Self-mode request; an old core answers `UnsupportedVersion`.
pub fn call(client: &mut Client, request: &SelfRequest) -> Result<SelfReply, String> {
    match client.call_self(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err((code, retry))) => Err(self_message(code, retry)),
        Err(e) => Err(client_message(&e)),
    }
}

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn new_password(prompt: &str) -> Result<Zeroizing<String>, String> {
    let p = term::read_secret(prompt, true, MAX_PASSWORD)?;
    if term::interactive() && p.chars().count() < MIN_NEW_PASSWORD {
        return Err(format!(
            "mot de passe trop court : au moins {MIN_NEW_PASSWORD} caractères."
        ));
    }
    Ok(p)
}

fn report_lines(r: &ImportReport) -> Vec<String> {
    let mut lines = vec![format!("{} secret(s) importé(s).", r.imported)];
    let mut note = |n: u64, what: &str| {
        if n > 0 {
            lines.push(format!("  {n} {what}"));
        }
    };
    note(
        r.empty,
        "entrée(s) vide(s) ignorée(s) (ni mot de passe ni notes).",
    );
    note(r.recycled, "entrée(s) de la corbeille KeePass ignorée(s).");
    note(
        r.refused,
        "entrée(s) refusée(s) par le coffre (valeur trop longue…).",
    );
    note(r.attachments, "pièce(s) jointe(s) non importée(s).");
    note(r.history, "version(s) antérieure(s) non importée(s).");
    note(r.totp, "configuration(s) TOTP non importée(s).");
    note(
        r.custom_skipped,
        "champ(s) personnalisé(s) au-delà des limites, non importé(s).",
    );
    lines
}

/// `import-kdbx FICHIER`.
pub fn import_kdbx(session: &Session<'_>, file: &Path) -> Result<(), String> {
    let path = std::fs::canonicalize(file).map_err(|_| "fichier introuvable.".to_owned())?;
    let path = path
        .to_str()
        .ok_or_else(|| "chemin non valide (UTF-8 attendu).".to_owned())?
        .to_owned();
    let mut c = session.connect(false)?;
    let password = term::read_secret("Mot de passe de la base KeePass : ", false, MAX_PASSWORD)?;
    eprintln!("Déchiffrement de la base… (cela peut prendre quelques secondes)");
    let SelfReply::Imported(r) = call(
        &mut c,
        &SelfRequest::ImportKdbx {
            path,
            password,
            locker: None,
        },
    )?
    else {
        return Err(unexpected());
    };
    for l in report_lines(&r) {
        say(&l);
    }
    Ok(())
}

fn date(wall_ms: u64) -> String {
    // Days since 1970-01-01 to a civil date (proleptic Gregorian), UTC.
    let secs = wall_ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (h, m) = ((secs % 86_400) / 3600, (secs % 3600) / 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

fn field_label(n: u64) -> &'static str {
    match n {
        1 => "titre",
        2 => "notes",
        3 => "favori",
        10 => "identifiant",
        11 => "mot de passe",
        12 => "TOTP",
        20 => "clé privée SSH",
        21 => "clé publique SSH",
        22 => "phrase de passe SSH",
        50 => "hôte",
        51 => "port",
        52 => "domaine",
        53 => "clé SSH liée",
        54 => "rebond",
        55 => "empreinte de l'hôte",
        _ => "autre champ",
    }
}

fn history_of(
    c: &mut Client,
    name: Option<&str>,
    id: Option<&str>,
) -> Result<(hirzla_core::proto::ListEntry, Vec<VersionInfo>), String> {
    let entry = resolve(c, name, id)?;
    let SelfReply::History(v) = call(
        c,
        &SelfRequest::History {
            locker: entry.locker,
            secret: entry.id,
        },
    )?
    else {
        return Err(unexpected());
    };
    Ok((entry, v))
}

/// `history NOM | --id ID`.
pub fn history(session: &Session<'_>, name: Option<&str>, id: Option<&str>) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let (_, versions) = history_of(&mut c, name, id)?;
    let mut out = std::io::stdout();
    for (i, v) in versions.iter().enumerate() {
        let state = match v.state {
            1 => " (corbeille)",
            2 => " (purgé)",
            _ => "",
        };
        let changed: Vec<&str> = v.changed.iter().map(|f| field_label(*f)).collect();
        let current = if i == 0 { "  ← actuelle" } else { "" };
        let _ = writeln!(
            out,
            "{:>3}  {}  {}{}  modifié : {}{}",
            i + 1,
            date(v.wall_ms),
            v.title.as_str(),
            state,
            if changed.is_empty() {
                "état".to_owned()
            } else {
                changed.join(", ")
            },
            current
        );
    }
    Ok(())
}

/// `restore NOM | --id ID [--version N] [--champ C --stdout]`: out of the trash, back to
/// version N, or one field of version N.
pub fn restore(
    session: &Session<'_>,
    name: Option<&str>,
    id: Option<&str>,
    version: Option<usize>,
) -> Result<(), String> {
    let mut c = session.connect(false)?;
    match version {
        None => {
            // A secret to take out of the trash is looked for there too.
            let entry = resolve_in(&mut c, name, id, true)?;
            call(
                &mut c,
                &SelfRequest::RestoreSecret {
                    locker: entry.locker,
                    secret: entry.id,
                },
            )?;
            say("Secret sorti de la corbeille.");
        }
        Some(n) => {
            let (entry, versions) = history_of(&mut c, name, id)?;
            let v = n
                .checked_sub(1)
                .and_then(|i| versions.get(i))
                .ok_or_else(|| "version introuvable (voir « hirzla history »).".to_owned())?;
            call(
                &mut c,
                &SelfRequest::RestoreVersion {
                    locker: entry.locker,
                    secret: entry.id,
                    version: v.op_id,
                },
            )?;
            say(&format!(
                "Version {n} rétablie : elle devient une nouvelle version du secret."
            ));
        }
    }
    Ok(())
}

/// `history NOM --version N --champ C`: one field of an earlier version.
pub fn read_version(
    session: &Session<'_>,
    name: Option<&str>,
    id: Option<&str>,
    version: usize,
    field: &str,
    stdout: bool,
) -> Result<(), String> {
    let field = field_by_name(field)?;
    let mut c = session.connect(false)?;
    let (entry, versions) = history_of(&mut c, name, id)?;
    let v = version
        .checked_sub(1)
        .and_then(|i| versions.get(i))
        .ok_or_else(|| "version introuvable (voir « hirzla history »).".to_owned())?;
    let SelfReply::Value(value) = call(
        &mut c,
        &SelfRequest::ReadVersion {
            locker: entry.locker,
            secret: entry.id,
            version: v.op_id,
            field,
        },
    )?
    else {
        return Err(unexpected());
    };
    let text = match value {
        ApiValue::Text(t) => t,
        ApiValue::Bool(b) => Zeroizing::new(if b { "oui" } else { "non" }.to_owned()),
    };
    let clear_s = crate::status(&mut c)?.clipboard_clear_s;
    crate::deliver(&text, stdout, clear_s)
}

/// `passwd`.
pub fn change_password(session: &Session<'_>) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let current = term::read_secret("Mot de passe maître actuel : ", false, MAX_PASSWORD)?;
    let new = new_password("Nouveau mot de passe maître : ")?;
    call(&mut c, &SelfRequest::ChangePassword { current, new })?;
    say("Mot de passe maître changé.");
    Ok(())
}

fn yes_no(v: &str, what: &str) -> Result<bool, String> {
    match v {
        "oui" | "yes" | "1" => Ok(true),
        "non" | "no" | "0" => Ok(false),
        _ => Err(format!("{what} : « oui » ou « non » attendu.")),
    }
}

/// Changes asked to the settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsChange {
    pub auto_lock_s: Option<u64>,
    pub clipboard_clear_s: Option<u64>,
    pub lock_on_sleep: Option<String>,
    pub lock_on_session_lock: Option<String>,
}

/// `settings [--verrouillage S] [--presse-papiers S] [--veille oui|non] [--session oui|non]`.
pub fn settings(session: &Session<'_>, change: &SettingsChange) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let SelfReply::Settings(mut s) = call(&mut c, &SelfRequest::GetSettings)? else {
        return Err(unexpected());
    };
    if change != &SettingsChange::default() {
        s = SettingsArgs {
            auto_lock_s: change.auto_lock_s.unwrap_or(s.auto_lock_s),
            clipboard_clear_s: change.clipboard_clear_s.unwrap_or(s.clipboard_clear_s),
            lock_on_sleep: change
                .lock_on_sleep
                .as_deref()
                .map(|v| yes_no(v, "--veille"))
                .transpose()?
                .unwrap_or(s.lock_on_sleep),
            lock_on_session_lock: change
                .lock_on_session_lock
                .as_deref()
                .map(|v| yes_no(v, "--session"))
                .transpose()?
                .unwrap_or(s.lock_on_session_lock),
        };
        call(&mut c, &SelfRequest::SetSettings(s)).map_err(|e| {
            if e.starts_with("valeur refusée") {
                "réglage refusé : verrouillage automatique de 30 à 86 400 s (ou 0 pour le \
                 défaut), effacement du presse-papiers de 5 à 600 s."
                    .to_owned()
            } else {
                e
            }
        })?;
        say("Réglages enregistrés.");
    }
    let on = |b: bool| if b { "oui" } else { "non" };
    say(&format!(
        "Verrouillage automatique : {} s.\nEffacement du presse-papiers : {} s.\n\
         Verrouillage à la mise en veille : {}.\nVerrouillage au verrouillage de la session : {}.",
        s.auto_lock_s,
        s.clipboard_clear_s,
        on(s.lock_on_sleep),
        on(s.lock_on_session_lock)
    ));
    Ok(())
}

/// Writes a new file, private to the user, refusing to replace one.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|_| format!("impossible de créer {} (existe déjà ?).", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| format!("écriture de {} impossible.", path.display()))
}

/// Reads a share file (at most 16 Kio) into an erasing buffer.
fn read_share(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let f =
        std::fs::File::open(path).map_err(|_| format!("impossible de lire {}.", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SHARE_FILE + 1));
    f.take(MAX_SHARE_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("impossible de lire {}.", path.display()))?;
    if bytes.len() > MAX_SHARE_FILE {
        return Err(format!(
            "{} n'est pas une part de recouvrement.",
            path.display()
        ));
    }
    Ok(bytes)
}

/// What `recovery` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    Status,
    Create {
        threshold: u8,
        count: u8,
        dir: PathBuf,
    },
    Unlock {
        files: Vec<PathBuf>,
    },
    Remove,
}

/// `recovery status | create T N DOSSIER | unlock PART… | remove`.
pub fn recovery(session: &Session<'_>, what: &Recovery) -> Result<(), String> {
    match what {
        Recovery::Status => {
            let mut c = session.connect(false)?;
            match call(&mut c, &SelfRequest::RecoveryStatus)? {
                SelfReply::RecoveryStatus(None) => say("Aucun kit de recouvrement."),
                SelfReply::RecoveryStatus(Some(i)) => say(&format!(
                    "Kit de recouvrement {} : {} parts sur {} rouvrent le coffre.",
                    hex(&i.kit_id[..4]),
                    i.threshold,
                    i.count
                )),
                _ => return Err(unexpected()),
            }
            Ok(())
        }
        Recovery::Create {
            threshold,
            count,
            dir,
        } => {
            if !dir.is_dir() {
                return Err(format!("{} n'est pas un dossier.", dir.display()));
            }
            let mut c = session.connect(false)?;
            let SelfReply::RecoveryKit { kit_id, shares } = call(
                &mut c,
                &SelfRequest::RecoveryCreate {
                    threshold: *threshold,
                    count: *count,
                },
            )?
            else {
                return Err(unexpected());
            };
            let tag = hex(&kit_id[..4]);
            for (i, share) in shares.iter().enumerate() {
                let path = dir.join(format!("hirzla-part-{tag}-{}.hirzla-part", i + 1));
                write_private(&path, share)?;
                say(&path.display().to_string());
            }
            say(&format!(
                "Kit {tag} créé : {threshold} parts sur {count} rouvrent le coffre. Remettez \
                 chaque part à une personne différente, puis effacez-les de ce poste. Un \
                 ancien kit ne fonctionne plus."
            ));
            Ok(())
        }
        Recovery::Unlock { files } => {
            let shares = files
                .iter()
                .map(|f| read_share(f))
                .collect::<Result<Vec<_>, _>>()?;
            let mut c = session.connect(true)?;
            let new_password = new_password("Nouveau mot de passe maître : ")?;
            call(
                &mut c,
                &SelfRequest::RecoveryUnlock {
                    shares,
                    new_password,
                },
            )?;
            say("Coffre ouvert avec le kit de recouvrement. Le nouveau mot de passe maître est en place.");
            Ok(())
        }
        Recovery::Remove => {
            let mut c = session.connect(false)?;
            call(&mut c, &SelfRequest::RecoveryRemove)?;
            say("Kit de recouvrement retiré : ses parts n'ouvrent plus le coffre.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hirzla_core::proto::ErrorCode;

    #[test]
    fn dates_are_civil_utc() {
        assert_eq!(date(0), "1970-01-01 00:00 UTC");
        assert_eq!(date(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(date(1_763_208_000_000 + 3_660_000), "2025-11-15 13:01 UTC");
    }

    #[test]
    fn messages_name_no_secret() {
        for c in [
            SelfCode::ImportUnsupported,
            SelfCode::ImportKeyRejected,
            SelfCode::ImportMalformed,
        ] {
            assert!(!self_message(c, None).is_empty());
        }
        assert!(self_message(SelfCode::General(ErrorCode::Throttled), Some(4)).contains('4'));
    }
}
