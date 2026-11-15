//! `hirzla-audit-verify`: independent verification of a Hirzla audit log
//! (`docs/evenements.md` § 6).
//!
//! It needs only the log file and the keeper's verifying key, compared out of band. It opens
//! no network connection and writes nothing but its standard outputs.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use hirzla_audit::export::{cef, json, syslog};
use hirzla_audit::field::{EntryHash, KeyFingerprint, LockerId};
use hirzla_audit::{
    encode_file, redact, verify_file, Checkpoint, Error, Keeper, KnownHead, Record, Scope,
    VerifyOptions,
};
use hirzla_crypto::sign::{VerifyingKey, VERIFYING_KEY_LEN};

const USAGE: &str = "\
Usage : hirzla-audit-verify --key <clé> [options] <journal>

Vérifie un journal d'audit Hirzla : chaîne SHA3-256 complète, points de contrôle signés
(ECDSA P-384 + ML-DSA-87) par la clé épinglée, dernier événement couvert.

Options :
  --key <fichier>               Clé de vérification du gardien (2 691 octets bruts ou en
                                hexadécimal). Comparez son empreinte hors bande.
  --keeper server|device        Gardien attendu (défaut : server).
  --known-checkpoint <fichier>  Point de contrôle conservé hors du journal (CBOR brut ou
                                hexadécimal, champ « cbor » de l'export JSON). Répétable.
  --known-head <seq>:<hex>      Tête connue d'une source de confiance (SIEM). Répétable.
  --scope-locker <hex>          N'exporter que les événements de ce casier ; les autres sont
                                masqués, la chaîne reste vérifiable. Répétable.
  --export json|cef|syslog|native
                                Après vérification, écrire le journal sur la sortie standard.
  --syslog-host <nom>           Champ HOSTNAME des messages syslog (défaut : -).
  -h, --help                    Afficher cette aide.

Codes de sortie : 0 journal valide, 1 journal invalide, 2 erreur d'usage ou de lecture.";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Cef,
    Syslog,
    Native,
}

struct Args {
    key: PathBuf,
    keeper: Keeper,
    known_checkpoints: Vec<PathBuf>,
    known_heads: Vec<KnownHead>,
    lockers: Vec<LockerId>,
    export: Option<Format>,
    syslog_host: String,
    log: PathBuf,
}

enum Failure {
    Usage(String),
    Invalid(Error),
}

fn usage(msg: &str) -> Failure {
    Failure::Usage(msg.to_owned())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Raw bytes of `expected` length, or hexadecimal text.
fn read_binary_or_hex(path: &PathBuf, expected: Option<usize>) -> Result<Vec<u8>, Failure> {
    let bytes = std::fs::read(path).map_err(|_| usage("fichier illisible"))?;
    if expected.is_some_and(|n| bytes.len() == n) {
        return Ok(bytes);
    }
    if let Some(decoded) = std::str::from_utf8(&bytes).ok().and_then(decode_hex) {
        return Ok(decoded);
    }
    Ok(bytes)
}

fn parse_args(raw: Vec<OsString>) -> Result<Args, Failure> {
    let mut key = None;
    let mut keeper = Keeper::Server;
    let mut known_checkpoints = Vec::new();
    let mut known_heads = Vec::new();
    let mut lockers = Vec::new();
    let mut export = None;
    let mut syslog_host = "-".to_owned();
    let mut log = None;
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        let Some(a) = arg.to_str() else {
            if log.replace(PathBuf::from(arg)).is_some() {
                return Err(usage("un seul journal à la fois"));
            }
            continue;
        };
        let mut value = || it.next().ok_or_else(|| usage("valeur manquante"));
        match a {
            "-h" | "--help" => return Err(Failure::Usage(String::new())),
            "--key" => key = Some(PathBuf::from(value()?)),
            "--keeper" => {
                keeper = match value()?.to_str() {
                    Some("server") => Keeper::Server,
                    Some("device") => Keeper::Device,
                    _ => return Err(usage("--keeper attend server ou device")),
                }
            }
            "--known-checkpoint" => known_checkpoints.push(PathBuf::from(value()?)),
            "--known-head" => {
                let v = value()?;
                let parsed = v.to_str().and_then(|s| {
                    let (seq, hex) = s.split_once(':')?;
                    let head: [u8; 32] = decode_hex(hex)?.try_into().ok()?;
                    Some(KnownHead {
                        seq: seq.parse().ok()?,
                        head: EntryHash::from_bytes(head),
                    })
                });
                known_heads.push(parsed.ok_or_else(|| usage("--known-head attend <seq>:<hex>"))?);
            }
            "--scope-locker" => {
                let v = value()?;
                let id: [u8; 16] = v
                    .to_str()
                    .and_then(decode_hex)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| usage("--scope-locker attend 16 octets en hexadécimal"))?;
                lockers.push(LockerId::from_bytes(id));
            }
            "--export" => {
                export = Some(match value()?.to_str() {
                    Some("json") => Format::Json,
                    Some("cef") => Format::Cef,
                    Some("syslog") => Format::Syslog,
                    Some("native") => Format::Native,
                    _ => return Err(usage("--export attend json, cef, syslog ou native")),
                })
            }
            "--syslog-host" => {
                syslog_host = value()?
                    .into_string()
                    .map_err(|_| usage("--syslog-host attend de l'ASCII"))?;
            }
            s if s.starts_with('-') => return Err(usage("option inconnue")),
            _ => {
                if log.replace(PathBuf::from(arg)).is_some() {
                    return Err(usage("un seul journal à la fois"));
                }
            }
        }
    }
    Ok(Args {
        key: key.ok_or_else(|| usage("--key est obligatoire"))?,
        keeper,
        known_checkpoints,
        known_heads,
        lockers,
        export,
        syslog_host,
        log: log.ok_or_else(|| usage("journal manquant"))?,
    })
}

fn run(args: &Args) -> Result<(), Failure> {
    let key_bytes = read_binary_or_hex(&args.key, Some(VERIFYING_KEY_LEN))?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| usage("clé de vérification invalide"))?;
    let mut known = args.known_heads.clone();
    for path in &args.known_checkpoints {
        let bytes = read_binary_or_hex(path, None)?;
        let cp = Checkpoint::from_bytes(&bytes).map_err(Failure::Invalid)?;
        known.push(KnownHead::from_checkpoint(&cp, &key, args.keeper).map_err(Failure::Invalid)?);
    }
    let log = std::fs::read(&args.log).map_err(|_| usage("journal illisible"))?;
    let options = VerifyOptions {
        key: &key,
        keeper: args.keeper,
        known: &known,
        allow_uncovered: false,
    };
    let (parsed, report) = verify_file(&log, &options).map_err(Failure::Invalid)?;

    let partial = match report.anchor {
        Some(seq) => {
            format!("Export partiel    : les séquences 0 à {seq} ne figurent pas dans ce fichier\n")
        }
        None => String::new(),
    };
    let summary = format!(
        "Journal valide.\n\
         Journal          : {}\n\
         Gardien          : {}\n\
         Empreinte de clé : {}\n\
         Séquences        : {} à {}\n\
         Événements       : {} visibles, {} masqués\n\
         Points de contrôle : {} (dernier : {})\n\
         Tête             : {}\n\
         Têtes connues    : {} vérifiées, {} antérieures au fichier\n\
         Retours d'horloge : {}\n\
         {partial}",
        report.log_id,
        report.keeper.name(),
        KeyFingerprint::of(&key),
        report.first_seq,
        report.last_seq,
        report.entries,
        report.elided,
        report.checkpoints,
        report.last_checkpoint,
        report.head,
        known.len() as u64 - report.known_unchecked,
        report.known_unchecked,
        report.time_regressions,
    );

    let Some(format) = args.export else {
        let mut out = std::io::stdout().lock();
        out.write_all(summary.as_bytes())
            .map_err(|_| usage("écriture impossible"))?;
        return Ok(());
    };
    eprint!("{summary}");
    let records = if args.lockers.is_empty() {
        parsed.records
    } else {
        redact(&parsed.records, &Scope::Lockers(args.lockers.clone())).map_err(Failure::Invalid)?
    };
    let log_id = parsed.header.log_id;
    let mut out: Vec<u8> = Vec::new();
    match format {
        Format::Native => {
            out = encode_file(parsed.header, &records).map_err(Failure::Invalid)?;
        }
        Format::Json => {
            for r in &records {
                out.extend_from_slice(
                    json::record_line(&log_id, r)
                        .map_err(Failure::Invalid)?
                        .as_bytes(),
                );
            }
        }
        Format::Cef => {
            for r in &records {
                let line = match r {
                    Record::Entry(e) => cef::entry(e).map_err(Failure::Invalid)?,
                    Record::Checkpoint(c) => cef::checkpoint(c),
                    Record::Elided(_) => continue,
                };
                out.extend_from_slice(line.as_bytes());
                out.push(b'\n');
            }
        }
        Format::Syslog => {
            let config = syslog::SyslogConfig::new(
                13,
                &args.syslog_host,
                "hirzla-audit",
                "-",
                syslog::DEFAULT_SD_ID,
            )
            .map_err(|_| usage("--syslog-host invalide"))?;
            for r in &records {
                let msg = match r {
                    Record::Entry(e) => syslog::entry(&config, e).map_err(Failure::Invalid)?,
                    Record::Checkpoint(c) => syslog::checkpoint(&config, c),
                    Record::Elided(_) => continue,
                };
                out.extend_from_slice(&syslog::frame(&msg));
            }
        }
    }
    std::io::stdout()
        .lock()
        .write_all(&out)
        .map_err(|_| usage("écriture impossible"))
}

/// French message for a refusal. Sequence numbers locate the fault; nothing else is shown.
fn explain(e: Error) -> String {
    match e {
        Error::Truncated => "fichier tronqué : un enregistrement est incomplet".to_owned(),
        Error::Malformed | Error::NonCanonical | Error::Limit | Error::Encoding => {
            "fichier mal formé ou non canonique".to_owned()
        }
        Error::UnsupportedVersion => "version ou type d'événement inconnu".to_owned(),
        Error::WrongLog => "enregistrement d'un autre journal ou d'un autre gardien".to_owned(),
        Error::BrokenChain(s) => format!(
            "chaîne rompue à la séquence {s} : événement supprimé, inséré, déplacé ou modifié"
        ),
        Error::MisplacedEvent(s) => format!("événement interdit à cette place, séquence {s}"),
        Error::CheckpointMismatch(s) => {
            format!("point de contrôle contredit par la chaîne, séquence {s}")
        }
        Error::BadSignature(s) => {
            format!("point de contrôle non signé par la clé épinglée, séquence {s}")
        }
        Error::NoCheckpoint => "aucun point de contrôle".to_owned(),
        Error::EmptyLog => "aucun événement dans le fichier".to_owned(),
        Error::Uncovered(s) => {
            format!("événements non couverts par un point de contrôle à partir de la séquence {s}")
        }
        Error::KnownCheckpointMissing(s) => {
            format!("la tête connue de la séquence {s} est absente : journal tronqué ou réécrit")
        }
        _ => "vérification impossible".to_owned(),
    }
}

fn main() -> ExitCode {
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = parse_args(raw).and_then(|args| run(&args));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(msg)) if msg.is_empty() => {
            let _ = writeln!(std::io::stdout().lock(), "{USAGE}");
            ExitCode::SUCCESS
        }
        Err(Failure::Usage(msg)) => {
            eprintln!("Erreur : {msg}.\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Invalid(e)) => {
            eprintln!("Journal invalide : {}.", explain(e));
            ExitCode::from(1)
        }
    }
}
