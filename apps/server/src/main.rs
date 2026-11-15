//! `hirzlad` — the blind server. It relays, orders and stores encrypted operations,
//! serves the key directory and keeps the audit log. It never holds a secret key
//! that could decrypt a user secret.
//!
//! ```text
//! hirzlad init  --data DIR --threshold T --shares N --shares-out DIR
//! hirzlad invitation --data DIR --address hirzla://HOST[:PORT] --ca PEM
//! hirzlad serve --data DIR --listen ADDR --cert PEM --key PEM
//!               --admin-listen ADDR --admin-cert PEM --admin-key PEM --admin-client-ca PEM
//! hirzlad admin etat|desceller|creer-compte|point-de-controle|arreter OPTIONS
//! ```
//!
//! One self-contained binary: no runtime dependency, no configuration service, no outbound
//! connection. `serve` starts sealed; custodians hand their shares over the administration
//! port until the quorum unseals the root key.

#![forbid(unsafe_code)]

mod admin;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hirzla_server::net::{self, Config};
use hirzla_server::seal::ShamirSeal;
use hirzla_server::store::{SealHeader, Store};
use hirzla_server::{tls, ServerError};
use hirzla_sync::text::{fingerprint, Invitation};

const USAGE: &str = "usage:
  hirzlad init  --data DIR --threshold T --shares N --shares-out DIR
  hirzlad invitation --data DIR --address hirzla://HOST[:PORT] --ca PEM
  hirzlad serve --data DIR --listen ADDR --cert PEM --key PEM \\
                --admin-listen ADDR --admin-cert PEM --admin-key PEM --admin-client-ca PEM
  hirzlad admin etat|desceller|creer-compte|point-de-controle|arreter …  (hirzlad admin aide)
  hirzlad --version";

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from(D[usize::from(x >> 4)]));
        s.push(char::from(D[usize::from(x & 15)]));
    }
    s
}

fn options(args: &[String]) -> Result<BTreeMap<String, String>, ServerError> {
    let mut m = BTreeMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let Some(name) = k.strip_prefix("--") else {
            return Err(ServerError::Config("unexpected argument"));
        };
        let v = it.next().ok_or(ServerError::Config("missing value"))?;
        if m.insert(name.to_owned(), v.clone()).is_some() {
            return Err(ServerError::Config("repeated option"));
        }
    }
    Ok(m)
}

fn get<'a>(o: &'a BTreeMap<String, String>, k: &'static str) -> Result<&'a str, ServerError> {
    o.get(k)
        .map(String::as_str)
        .ok_or(ServerError::Config("missing option"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ServerError> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn init(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    let dir = PathBuf::from(get(o, "data")?);
    let out = PathBuf::from(get(o, "shares-out")?);
    let threshold: u8 = get(o, "threshold")?
        .parse()
        .map_err(|_| ServerError::Config("threshold"))?;
    let count: u8 = get(o, "shares")?
        .parse()
        .map_err(|_| ServerError::Config("shares"))?;
    let setup = ShamirSeal::generate(threshold, count)?;
    let header = Store::init(&dir, &setup.seal, Some(setup.dealer.clone()))?;
    std::fs::create_dir_all(&out)?;
    for s in &setup.shares {
        write_private(&out.join(format!("share-{}.bin", s.index())), s.as_bytes())?;
    }
    report(&format!(
        "server_id {}\nserver_key_fingerprint {}\nfingerprint {}\nshares {count}, threshold {threshold}: hand one to each custodian, then delete {}",
        hex(&header.server_id),
        hex(&hirzla_crypto::util::sha384(header.server_key.as_bytes())),
        fingerprint(header.server_key.as_bytes()),
        out.display()
    ));
    Ok(())
}

/// Writes the invitation link (`sync-protocol.md` § 11.10, ADR 0046) on standard output:
/// the address, the site CA and the fingerprint of the server key, read from the clear
/// header of the data directory without unsealing it.
fn invitation(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    let header = SealHeader::read(Path::new(get(o, "data")?))?;
    let address = get(o, "address")?;
    let ok = address
        .strip_prefix("hirzla://")
        .is_some_and(|h| !h.is_empty() && !h.contains(['/', '@', '?', '#']));
    if !ok {
        return Err(ServerError::Config("the address is hirzla://HOST[:PORT]"));
    }
    let ca = Path::new(get(o, "ca")?);
    tls::load_certs(ca)?;
    let roots = std::fs::read(ca)?;
    let link = Invitation {
        address: address.to_owned(),
        roots,
        fingerprint: fingerprint(header.server_key.as_bytes()),
    }
    .encode()
    .map_err(|_| ServerError::Config("the CA is too large for a link"))?;
    writeln!(std::io::stdout().lock(), "{link}")?;
    Ok(())
}

fn addr(o: &BTreeMap<String, String>, k: &'static str) -> Result<SocketAddr, ServerError> {
    // Addresses only: a name would need a resolver, that is an outbound request.
    get(o, k)?
        .parse()
        .map_err(|_| ServerError::Config("an address is IP:port, never a name"))
}

fn serve(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    let device_tls = tls::device_server_config(
        tls::load_certs(Path::new(get(o, "cert")?))?,
        tls::load_key(Path::new(get(o, "key")?))?,
    )?;
    let admin_tls = tls::admin_server_config(
        tls::load_certs(Path::new(get(o, "admin-cert")?))?,
        tls::load_key(Path::new(get(o, "admin-key")?))?,
        tls::roots(tls::load_certs(Path::new(get(o, "admin-client-ca")?))?)?,
    )?;
    let running = net::start(Config {
        data_dir: PathBuf::from(get(o, "data")?),
        listen: addr(o, "listen")?,
        admin_listen: addr(o, "admin-listen")?,
        tls: device_tls,
        admin_tls,
    })?;
    report(&format!(
        "listening {} admin {} (sealed)",
        running.addr, running.admin_addr
    ));
    running.wait();
    Ok(())
}

/// Operator output: to standard error, so that standard output stays free for scripting.
fn report(s: &str) {
    eprintln!("hirzlad: {s}");
}

/// Output of the administration tool, to standard error like the rest of `hirzlad`.
fn report_admin(s: &str) {
    eprintln!("{s}");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--version") => {
            report(env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("init") => options(&args[1..]).and_then(|o| init(&o)),
        Some("invitation") => options(&args[1..]).and_then(|o| invitation(&o)),
        Some("serve") => options(&args[1..]).and_then(|o| serve(&o)),
        // Administration tool (ADR 0053): French messages, its own exit codes.
        Some("admin") => {
            return match args.get(1).map(String::as_str) {
                Some("aide" | "--help" | "-h") | None => {
                    report_admin(admin::USAGE);
                    ExitCode::SUCCESS
                }
                _ => match admin::run(&args[1..]) {
                    Ok(text) => {
                        report_admin(&text);
                        ExitCode::SUCCESS
                    }
                    Err(msg) => {
                        report_admin(&format!("erreur : {msg}"));
                        ExitCode::from(1)
                    }
                },
            };
        }
        _ => Err(ServerError::Config("unknown command")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report(&format!("{e}\n{USAGE}"));
            ExitCode::from(2)
        }
    }
}
