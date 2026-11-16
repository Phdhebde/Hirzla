//! `hirzlad admin`: the administration tool of the server (ADR 0053), in French, over the
//! administration port (TLS 1.3 hybrid, administrator certificate).
//!
//! ```text
//! hirzlad admin etat              OPTIONS
//! hirzlad admin desceller         OPTIONS --part FICHIER
//! hirzlad admin creer-compte      OPTIONS --membre FICHIER [--empreinte EMPREINTE]
//! hirzlad admin point-de-controle OPTIONS --sortie FICHIER
//! hirzlad admin arreter           OPTIONS
//!
//! OPTIONS : --serveur IP:PORT --nom NOM --ac PEM --certificat PEM --cle PEM
//! ```
//!
//! What crosses the administration port (rule 3 of `CLAUDE.md`, the server stays blind):
//!
//! - `desceller`: one custodian share of the **server's own** root key (ADR 0028), the only
//!   way to unseal it. It decrypts the server's storage, never a user secret, which stays
//!   end-to-end encrypted under keys the server never holds. The share is read from its file
//!   into an erasing buffer and never printed.
//! - `creer-compte`: the **public** member keys exported by `hirzla serveur identite
//!   --sortie`. Their fingerprint is shown, and compared to `--empreinte` when given, so that
//!   the administrator checks the file out of band before the account exists.
//! - `point-de-controle`: a signed audit checkpoint, public.
//!
//! The server is named by its IP address only: a name would need a resolver, an outbound
//! request (rule 7). `--nom` is the name in the server's TLS certificate, never resolved.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use hirzla_crypto::util::sha384;
use hirzla_server::client::AdminClient;
use hirzla_server::proto::{code, AdminStatus};
use hirzla_server::{tls, ServerError};
use hirzla_vault::model::MemberKeys;
use zeroize::Zeroizing;

/// Usage of `hirzlad admin`, in French.
pub const USAGE: &str = "usage :
  hirzlad admin etat              OPTIONS
        État du sceau : scellé ou descellé, parts reçues, empreinte de la clé du serveur.
  hirzlad admin desceller         OPTIONS --part FICHIER
        Remet la part d'un dépositaire (fichier share-N.bin de « hirzlad init »).
  hirzlad admin creer-compte      OPTIONS --membre FICHIER [--empreinte EMPREINTE]
        Crée le compte d'un membre à partir de sa clé publique (« hirzla serveur
        identite --sortie »). Avec --empreinte, refuse une clé d'une autre empreinte.
  hirzlad admin point-de-controle OPTIONS --sortie FICHIER
        Fait signer un point de contrôle du journal d'audit et l'écrit dans FICHIER.
  hirzlad admin arreter           OPTIONS
        Arrête le serveur proprement.

OPTIONS (toutes obligatoires) :
  --serveur IP:PORT   adresse du port d'administration (une adresse IP, jamais un nom)
  --nom NOM           nom inscrit dans le certificat TLS du serveur
  --ac PEM            autorité de certification qui a émis le certificat du serveur
  --certificat PEM    votre certificat d'administrateur
  --cle PEM           la clé privée de ce certificat";

/// Largest share file accepted (a share is a few kilobytes; the server takes 64 KiB).
const MAX_SHARE: u64 = 64 * 1024;
/// Largest member key file accepted.
const MAX_MEMBER_KEYS: u64 = 64 * 1024;
/// Length of a member key fingerprint (`format.md` § 3.1).
const FINGERPRINT_LEN: usize = 20;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Runs `hirzlad admin …` and returns the text for the operator, or an error message in
/// French.
///
/// # Errors
/// A message for the operator.
pub fn run(args: &[String]) -> Result<String, String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(format!("commande manquante.\n{USAGE}"));
    };
    let o = options(rest)?;
    let allowed: &[&str] = match command.as_str() {
        "etat" | "arreter" => &[],
        "desceller" => &["part"],
        "creer-compte" => &["membre", "empreinte"],
        "point-de-controle" => &["sortie"],
        _ => return Err(format!("commande inconnue : {command}.\n{USAGE}")),
    };
    for k in o.keys() {
        let common = ["serveur", "nom", "ac", "certificat", "cle"];
        if !common.contains(&k.as_str()) && !allowed.contains(&k.as_str()) {
            return Err(format!("option inconnue pour {command} : --{k}."));
        }
    }
    // Read and check the local files before connecting: nothing is sent on a bad input.
    match command.as_str() {
        "desceller" => {
            let share = read_limited(Path::new(get(&o, "part")?), MAX_SHARE, "part")?;
            let mut c = connect(&o)?;
            let st = c.unseal(&share).map_err(|e| refused(&e, "part"))?;
            Ok(format!("Part acceptée.\n{}", status_text(&st)))
        }
        "creer-compte" => {
            let bytes = read_limited(Path::new(get(&o, "membre")?), MAX_MEMBER_KEYS, "clé")?;
            let keys = member_keys(&bytes)?;
            let fp = fingerprint(&keys.sig);
            if let Some(expected) = o.get("empreinte") {
                if normalise(expected).as_deref() != Some(fp.as_str()) {
                    return Err(format!(
                        "empreinte différente : le fichier porte la clé {}. Aucun compte n'a \
                         été créé ; vérifiez le fichier avec le membre.",
                        grouped(&fp)
                    ));
                }
            }
            let mut c = connect(&o)?;
            let (account, index) = c.create_account(&keys).map_err(|e| refused(&e, "compte"))?;
            Ok(format!(
                "Compte créé.\nMembre : {}\nEmpreinte de la clé de membre : {}\nCompte : {}\n\
                 Rang dans le journal des clés : {index}",
                hex(&keys.member),
                grouped(&fp),
                hex(&account),
            ))
        }
        "point-de-controle" => {
            let out = Path::new(get(&o, "sortie")?);
            let mut c = connect(&o)?;
            let cp = c.checkpoint().map_err(|e| refused(&e, "point"))?;
            write_new(out, &cp)?;
            Ok(format!(
                "Point de contrôle signé écrit dans {} ({} octets). Vérifiez-le avec \
                 hirzla-audit-verify.",
                out.display(),
                cp.len()
            ))
        }
        "arreter" => {
            connect(&o)?.shutdown().map_err(|e| refused(&e, "arrêt"))?;
            Ok("Arrêt demandé : le serveur termine ses connexions puis s'arrête.".to_owned())
        }
        _ => {
            let st = connect(&o)?.status().map_err(|e| refused(&e, "état"))?;
            Ok(status_text(&st))
        }
    }
}

fn options(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut m = BTreeMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let Some(name) = k.strip_prefix("--") else {
            return Err(format!("argument inattendu : {k}."));
        };
        let v = it
            .next()
            .ok_or_else(|| format!("valeur manquante pour --{name}."))?;
        if m.insert(name.to_owned(), v.clone()).is_some() {
            return Err(format!("option répétée : --{name}."));
        }
    }
    Ok(m)
}

fn get<'a>(o: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str, String> {
    o.get(k)
        .map(String::as_str)
        .ok_or_else(|| format!("option manquante : --{k}.\n{USAGE}"))
}

fn connect(o: &BTreeMap<String, String>) -> Result<AdminClient, String> {
    let addr: SocketAddr = get(o, "serveur")?
        .parse()
        .map_err(|_| "--serveur attend une adresse IP:PORT, jamais un nom.".to_owned())?;
    let name = get(o, "nom")?;
    let roots = tls::load_certs(Path::new(get(o, "ac")?))
        .and_then(tls::roots)
        .map_err(|_| "autorité de certification illisible (--ac).".to_owned())?;
    let certs = tls::load_certs(Path::new(get(o, "certificat")?))
        .map_err(|_| "certificat d'administrateur illisible (--certificat).".to_owned())?;
    let key = tls::load_key(Path::new(get(o, "cle")?))
        .map_err(|_| "clé privée illisible (--cle).".to_owned())?;
    let config = tls::client_config(roots, Some((certs, key)))
        .map_err(|_| "certificat ou clé d'administrateur refusés.".to_owned())?;
    AdminClient::connect(addr, name, &config).map_err(|_| {
        "connexion impossible : serveur injoignable, certificat du serveur non reconnu ou \
         certificat d'administrateur refusé."
            .to_owned()
    })
}

/// The operator's message for a refusal; never a detail of the input.
fn refused(e: &ServerError, what: &str) -> String {
    match (e, what) {
        (ServerError::Refused(code::AUTH), "part") => {
            "part refusée : elle n'appartient pas à ce serveur, est altérée ou a déjà été remise."
                .to_owned()
        }
        (ServerError::Refused(code::ACCESS), "compte") => {
            "compte refusé : clé de membre non valide ou déjà inscrite.".to_owned()
        }
        (ServerError::Refused(code::UNAVAILABLE), "part") => {
            "le serveur n'a pas pu se desceller (stockage indisponible).".to_owned()
        }
        (ServerError::Refused(code::UNAVAILABLE), _) => {
            "le serveur est scellé ou indisponible : descellez-le d'abord.".to_owned()
        }
        (ServerError::Refused(_), _) => "requête refusée par le serveur.".to_owned(),
        _ => "échange interrompu avec le serveur.".to_owned(),
    }
}

/// Reads a whole file of at most `max` bytes into an erasing buffer.
fn read_limited(path: &Path, max: u64, what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new(Vec::with_capacity(4096));
    std::fs::File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut buf))
        .map_err(|_| format!("fichier de {what} illisible : {}.", path.display()))?;
    if buf.len() as u64 > max || buf.is_empty() {
        return Err(format!(
            "fichier de {what} non valide : {}.",
            path.display()
        ));
    }
    Ok(buf)
}

fn member_keys(bytes: &[u8]) -> Result<MemberKeys, String> {
    hirzla_vault::cbor::decode(bytes)
        .ok()
        .and_then(|v| MemberKeys::from_value(&v).ok())
        .ok_or_else(|| {
            "fichier de clé de membre non valide (attendu : « hirzla serveur identite --sortie »)."
                .to_owned()
        })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            format!(
                "écriture impossible (le fichier existe-t-il déjà ?) : {}.",
                path.display()
            )
        })?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| format!("écriture impossible : {}.", path.display()))
}

fn status_text(st: &AdminStatus) -> String {
    let state = if st.sealed { "scellé" } else { "descellé" };
    let shares = if st.threshold > 0 {
        format!("{} sur {}", st.shares, st.threshold)
    } else {
        st.shares.to_string()
    };
    format!(
        "État : {state}\nParts reçues : {shares}\nServeur : {}\nEmpreinte de la clé du serveur : {}",
        hex(&st.server_id),
        hex(&st.server_key_fingerprint)
    )
}

/// Fingerprint of a public key (`format.md` § 3.1): the first 20 characters of the RFC 4648
/// base32 of SHA-384(key), as `hirzla serveur identite` shows it. A display encoding.
fn fingerprint(key: &[u8]) -> String {
    let hash = sha384(key);
    let mut out = String::with_capacity(FINGERPRINT_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in hash {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < FINGERPRINT_LEN {
            bits -= 5;
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
        if out.len() == FINGERPRINT_LEN {
            break;
        }
    }
    out
}

/// A typed fingerprint, without spaces or dashes, in capitals; `None` if it is not 20
/// characters of the base32 alphabet.
fn normalise(typed: &str) -> Option<String> {
    let s: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (s.len() == FINGERPRINT_LEN && s.bytes().all(|b| BASE32.contains(&b))).then_some(s)
}

fn grouped(fp: &str) -> String {
    fp.as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from(D[usize::from(x >> 4)]));
        s.push(char::from(D[usize::from(x & 15)]));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn fingerprint_matches_the_core_display() {
        // Same value as `hirzla_core::server_mode::fingerprint(b"key")`: the first 20
        // characters of base32(SHA-384("key")).
        assert_eq!(fingerprint(b"key"), "DN2FUDKQAMBOMKMGJYVG");
        assert_eq!(
            normalise("dn2fu dkqam-bomkm gjyvg").as_deref(),
            Some("DN2FUDKQAMBOMKMGJYVG")
        );
        assert_eq!(normalise("DN2FUDKQAMBOMKMGJYV1"), None);
        assert_eq!(normalise("DN2FU"), None);
    }

    #[test]
    fn unknown_commands_and_options_are_refused_before_any_connection() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert!(run(&s(&[])).is_err());
        assert!(run(&s(&["inconnue"]))
            .unwrap_err()
            .contains("commande inconnue"));
        assert!(run(&s(&["etat", "--part", "x"]))
            .unwrap_err()
            .contains("option inconnue"));
        assert!(run(&s(&["etat", "--serveur"]))
            .unwrap_err()
            .contains("valeur manquante"));
        assert!(run(&s(&["desceller", "--part", "/nonexistent/share"]))
            .unwrap_err()
            .contains("illisible"));
        let e = run(&s(&[
            "etat",
            "--serveur",
            "hirzlad.example:4443",
            "--nom",
            "x",
            "--ac",
            "a",
            "--certificat",
            "c",
            "--cle",
            "k",
        ]))
        .unwrap_err();
        assert!(e.contains("jamais un nom"), "{e}");
    }
}
