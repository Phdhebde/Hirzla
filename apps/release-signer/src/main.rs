//! `hirzla-signer` — the publisher's signing tool (ADR 0042, 0043; `docs/livraison.md` § 7
//! and § 8). It runs on the publisher's offline signing station, never on a workstation and
//! never on a CI agent: it holds the private publisher key.
//!
//! The private key file holds the encoded private key (82 bytes) followed by the encoded
//! public key (2 691 bytes); it is created with mode 0600 and never overwritten. Messages
//! are in French; no key material is ever printed, except the public key by `cle-hex`.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hirzla_core::release::update::{verify_package, write_package, PackageInput};
use hirzla_core::release::{
    current_platform, load_client_manifest, sign, update, Kind, Manifest, PublisherKeys, Version,
    CLIENT_MANIFEST_FILE, HEADER_LEN, MAGIC,
};
use hirzla_crypto::sign::{PublisherSigningKey, VerifyingKey, SIGNING_KEY_LEN, VERIFYING_KEY_LEN};
use zeroize::Zeroizing;

const USAGE: &str = "\
Usage : hirzla-signer COMMANDE [ARGUMENTS]

  cle-generer --prive FICHIER --publique FICHIER
        Crée une clé d'éditeur hybride (ECDSA P-384 + ML-DSA-87). Le fichier privé est créé
        en 0600 et n'écrase jamais un fichier existant.
  cle-hex --publique FICHIER
        Affiche la clé publique en hexadécimal, pour HIRZLA_PUBLISHER_KEYS.
  manifeste-clients --cle FICHIER --version X.Y.Z [--plateforme P] --sortie FICHIER EXÉCUTABLE…
        Signe le manifeste des clients (empreintes SHA-384 des exécutables installés).
  paquet --cle FICHIER --version X.Y.Z [--plateforme P] --sortie FICHIER FICHIER…
        Construit et signe un paquet de mise à jour hors ligne.
  verifier --publique FICHIER FICHIER
        Vérifie un manifeste des clients ou un paquet de mise à jour.

Plateforme par défaut : celle de cet outil (par exemple linux-x86_64).";

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("hirzla-signer : {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Options and positional arguments of one command.
struct Parsed {
    options: Vec<(String, PathBuf)>,
    positional: Vec<PathBuf>,
}

impl Parsed {
    fn new(args: Vec<OsString>, allowed: &[&str]) -> Result<Parsed, String> {
        let mut options = Vec::new();
        let mut positional = Vec::new();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.to_str() {
                Some(name) if name.starts_with("--") => {
                    if !allowed.contains(&name) {
                        return Err(format!("option inconnue : {name}\n\n{USAGE}"));
                    }
                    if options.iter().any(|(n, _)| n == name) {
                        return Err(format!("{name} ne peut être donné qu'une fois."));
                    }
                    let v = it
                        .next()
                        .ok_or_else(|| format!("{name} attend une valeur."))?;
                    options.push((name.to_owned(), PathBuf::from(v)));
                }
                _ => positional.push(PathBuf::from(a)),
            }
        }
        Ok(Parsed {
            options,
            positional,
        })
    }

    fn opt(&self, name: &str) -> Option<&Path> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_path())
    }

    fn req(&self, name: &str) -> Result<&Path, String> {
        self.opt(name)
            .ok_or_else(|| format!("{name} est obligatoire.\n\n{USAGE}"))
    }

    fn text(&self, name: &str) -> Result<Option<String>, String> {
        self.opt(name)
            .map(|p| {
                p.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{name} : texte non valide."))
            })
            .transpose()
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    let mut it = args.into_iter();
    let command = it.next().ok_or_else(|| USAGE.to_owned())?;
    let rest: Vec<OsString> = it.collect();
    match command.to_str() {
        Some("cle-generer") => generate(&Parsed::new(rest, &["--prive", "--publique"])?),
        Some("cle-hex") => key_hex(&Parsed::new(rest, &["--publique"])?),
        Some("manifeste-clients") => client_manifest(&Parsed::new(
            rest,
            &["--cle", "--version", "--plateforme", "--sortie"],
        )?),
        Some("paquet") => package(&Parsed::new(
            rest,
            &["--cle", "--version", "--plateforme", "--sortie"],
        )?),
        Some("verifier") => verify(&Parsed::new(rest, &["--publique"])?),
        Some("-h" | "--help" | "aide") => Err(USAGE.to_owned()),
        _ => Err(format!("commande inconnue.\n\n{USAGE}")),
    }
}

fn create_new(path: &Path, private: bool) -> Result<File, String> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    o.open(path).map_err(|_| {
        format!(
            "impossible de créer {} (existe-t-il déjà ?).",
            path.display()
        )
    })
}

fn generate(p: &Parsed) -> Result<(), String> {
    let private = p.req("--prive")?;
    let public = p.req("--publique")?;
    let key = PublisherSigningKey::generate().map_err(|_| "génération impossible.".to_owned())?;
    let secret = key
        .to_bytes()
        .map_err(|_| "encodage de la clé impossible.".to_owned())?;
    let mut f = create_new(private, true)?;
    f.write_all(&secret)
        .and_then(|()| f.write_all(key.verifying_key().as_bytes()))
        .and_then(|()| f.sync_all())
        .map_err(|_| "écriture de la clé privée impossible.".to_owned())?;
    let mut f = create_new(public, false)?;
    f.write_all(key.verifying_key().as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| "écriture de la clé publique impossible.".to_owned())?;
    say("Clé d'éditeur créée. Gardez le fichier privé hors ligne ; ne le commitez jamais.");
    Ok(())
}

fn read_public(path: &Path) -> Result<VerifyingKey, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(VERIFYING_KEY_LEN as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "clé publique illisible.".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "clé publique invalide.".to_owned())
}

fn read_private(path: &Path) -> Result<PublisherSigningKey, String> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(SIGNING_KEY_LEN + VERIFYING_KEY_LEN + 1));
    File::open(path)
        .and_then(|f| {
            f.take((SIGNING_KEY_LEN + VERIFYING_KEY_LEN + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| "clé privée illisible.".to_owned())?;
    if bytes.len() != SIGNING_KEY_LEN + VERIFYING_KEY_LEN {
        return Err("clé privée invalide.".to_owned());
    }
    let public = VerifyingKey::from_bytes(&bytes[SIGNING_KEY_LEN..])
        .map_err(|_| "clé privée invalide.".to_owned())?;
    PublisherSigningKey::from_bytes(&bytes[..SIGNING_KEY_LEN], &public)
        .map_err(|_| "clé privée invalide.".to_owned())
}

fn key_hex(p: &Parsed) -> Result<(), String> {
    let key = read_public(p.req("--publique")?)?;
    say(&key
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>());
    Ok(())
}

fn version_and_platform(p: &Parsed) -> Result<(Version, String), String> {
    let version = p
        .text("--version")?
        .ok_or_else(|| format!("--version est obligatoire.\n\n{USAGE}"))?;
    let version = Version::parse(&version).ok_or_else(|| "--version attend X.Y.Z.".to_owned())?;
    let platform = p.text("--plateforme")?.unwrap_or_else(current_platform);
    Ok((version, platform))
}

fn file_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("nom de fichier non valide : {}", path.display()))
}

fn client_manifest(p: &Parsed) -> Result<(), String> {
    let key = read_private(p.req("--cle")?)?;
    let (version, platform) = version_and_platform(p)?;
    if p.positional.is_empty() {
        return Err("indiquez au moins un EXÉCUTABLE.".to_owned());
    }
    let mut files = Vec::new();
    for path in &p.positional {
        files.push(
            update::entry_for(&file_name(path)?, path, true)
                .map_err(|_| format!("{} illisible.", path.display()))?,
        );
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let manifest = Manifest {
        version,
        platform,
        files,
    };
    let bytes = sign(Kind::ClientManifest, &manifest, &key)
        .map_err(|e| format!("manifeste refusé : {e}."))?;
    let mut f = create_new(p.req("--sortie")?, false)?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| "écriture du manifeste impossible.".to_owned())?;
    say(&format!(
        "Manifeste des clients {version} signé ({} exécutables).",
        manifest.files.len()
    ));
    Ok(())
}

fn package(p: &Parsed) -> Result<(), String> {
    let key = read_private(p.req("--cle")?)?;
    let (version, platform) = version_and_platform(p)?;
    if p.positional.is_empty() {
        return Err("indiquez au moins un FICHIER.".to_owned());
    }
    let mut inputs = Vec::new();
    for path in &p.positional {
        let name = file_name(path)?;
        inputs.push(PackageInput {
            executable: name != CLIENT_MANIFEST_FILE,
            name,
            path: path.clone(),
        });
    }
    let out_path = p.req("--sortie")?;
    let mut out = BufWriter::new(create_new(out_path, false)?);
    let written = write_package(version, &platform, &inputs, &key, &mut out);
    let finished = written.and_then(|m| {
        out.into_inner()
            .map_err(|_| hirzla_core::release::ReleaseError::Io)?
            .sync_all()
            .map_err(|_| hirzla_core::release::ReleaseError::Io)?;
        Ok(m)
    });
    match finished {
        Ok(m) => {
            say(&format!(
                "Paquet {} pour {} signé ({} fichiers).",
                m.version,
                m.platform,
                m.files.len()
            ));
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(out_path);
            Err(format!("paquet refusé : {e}."))
        }
    }
}

fn verify(p: &Parsed) -> Result<(), String> {
    let keys = PublisherKeys::new(vec![read_public(p.req("--publique")?)?]);
    let [file] = p.positional.as_slice() else {
        return Err(format!("indiquez un FICHIER.\n\n{USAGE}"));
    };
    let mut head = [0u8; HEADER_LEN];
    File::open(file)
        .and_then(|mut f| f.read_exact(&mut head))
        .map_err(|_| "fichier illisible ou trop court.".to_owned())?;
    let (what, m) = if head[..6] == MAGIC[..] && head[6] == b'C' {
        ("Manifeste des clients", load_client_manifest(file, &keys))
    } else {
        ("Paquet de mise à jour", verify_package(file, &keys))
    };
    let m = m.map_err(|e| format!("refusé : {e}."))?;
    say(&format!(
        "{what} {} pour {} : authentique.",
        m.version, m.platform
    ));
    for f in &m.files {
        say(&format!("  {}  {} octets", f.name, f.size));
    }
    Ok(())
}

fn say(text: &str) {
    let _ = writeln!(std::io::stdout(), "{text}");
}
