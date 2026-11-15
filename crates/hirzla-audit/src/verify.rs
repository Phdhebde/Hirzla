//! Log files and their independent verification (`docs/evenements.md` § 5 and § 6).
//!
//! A log file is a CBOR sequence: a header, then records. The verifier needs only the file and
//! the keeper's verifying key, pinned by the reader; it trusts nothing else in the file.

use std::collections::BTreeMap;

use hirzla_crypto::sign::VerifyingKey;

use crate::cbor::{self, Fields, Value};
use crate::chain::{check_placement, Checkpoint, Keeper, Record, VERSION};
use crate::field::{EntryHash, LockerId, LogId};
use crate::Error;

/// Magic text of a log file header.
pub const MAGIC: &str = "hirzla-audit";

/// Most records accepted in one file.
pub const MAX_RECORDS: usize = 1 << 26;

/// Longest incomplete trailing record the keeper cuts when it reopens its log. A record is at
/// most a few kilobytes (a checkpoint is about 4.9 kB): a longer cut is not a crash.
pub const MAX_TORN_TAIL: usize = 64 * 1024;

/// The first item of a log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Log.
    pub log_id: LogId,
    /// Keeper.
    pub keeper: Keeper,
}

impl Header {
    fn to_value(self) -> Value {
        Value::Map(vec![
            (1, Value::Text(MAGIC.to_owned())),
            (2, Value::Uint(VERSION)),
            (3, Value::bytes(self.log_id.as_bytes())),
            (4, Value::Uint(self.keeper.code())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        if cbor::text(f.req(1)?)? != MAGIC {
            return Err(Error::Malformed);
        }
        if cbor::uint(f.req(2)?)? != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let keeper = match cbor::uint(f.req(4)?)? {
            1 => Keeper::Server,
            2 => Keeper::Device,
            _ => return Err(Error::Malformed),
        };
        Ok(Header {
            log_id: LogId::from_bytes(cbor::fixed(f.req(3)?)?),
            keeper,
        })
    }

    /// Canonical encoding.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn to_bytes(self) -> Result<Vec<u8>, Error> {
        cbor::encode(&self.to_value())
    }
}

/// Encodes a whole file.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn encode_file(header: Header, records: &[Record]) -> Result<Vec<u8>, Error> {
    let mut out = header.to_bytes()?;
    for r in records {
        out.extend_from_slice(&r.to_bytes()?);
    }
    Ok(out)
}

/// A parsed file, before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFile {
    /// Header.
    pub header: Header,
    /// Records, in file order.
    pub records: Vec<Record>,
    /// Length of the complete records, header included.
    pub complete_len: usize,
    /// Whether an incomplete record followed them (crash during a write).
    pub torn_tail: bool,
}

/// Parses a file strictly: any cut, malformed or non-canonical item is refused.
///
/// # Errors
/// [`Error::Truncated`] on a cut record, and the decoding errors of [`Error`].
pub fn parse_file(bytes: &[u8]) -> Result<ParsedFile, Error> {
    let parsed = parse(bytes, false)?;
    if parsed.torn_tail {
        return Err(Error::Truncated);
    }
    Ok(parsed)
}

/// Parses a file, accepting a cut last record, which the keeper may cut off when it reopens
/// its own log after a crash.
///
/// # Errors
/// The decoding errors of [`Error`].
pub fn parse_file_lenient(bytes: &[u8]) -> Result<ParsedFile, Error> {
    parse(bytes, true)
}

fn parse(bytes: &[u8], lenient: bool) -> Result<ParsedFile, Error> {
    let (h, mut pos) = cbor::decode_one(bytes)?;
    let header = Header::from_value(&h)?;
    let mut records = Vec::new();
    while pos < bytes.len() {
        if records.len() >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        match cbor::decode_one(&bytes[pos..]) {
            Ok((v, used)) => {
                records.push(Record::from_value(&v)?);
                pos += used;
            }
            Err(Error::Truncated) if lenient && bytes.len() - pos <= MAX_TORN_TAIL => {
                return Ok(ParsedFile {
                    header,
                    records,
                    complete_len: pos,
                    torn_tail: true,
                })
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ParsedFile {
        header,
        records,
        complete_len: pos,
        torn_tail: false,
    })
}

/// A head known outside the log: a checkpoint kept by a SIEM or an auditor. If the log no
/// longer holds this hash at this sequence number, it was truncated or rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownHead {
    /// Sequence number.
    pub seq: u64,
    /// Hash of that entry.
    pub head: EntryHash,
}

impl KnownHead {
    /// The head of a checkpoint, after checking its signature.
    ///
    /// # Errors
    /// [`Error::BadSignature`].
    pub fn from_checkpoint(
        checkpoint: &Checkpoint,
        key: &VerifyingKey,
        keeper: Keeper,
    ) -> Result<Self, Error> {
        checkpoint.verify(key, keeper)?;
        Ok(KnownHead {
            seq: checkpoint.seq,
            head: checkpoint.head,
        })
    }
}

/// What the verifier is given besides the file.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'a> {
    /// The keeper's verifying key, pinned by the reader (never taken from the file).
    pub key: &'a VerifyingKey,
    /// The expected keeper.
    pub keeper: Keeper,
    /// Heads known outside the log.
    pub known: &'a [KnownHead],
    /// Accept entries after the last checkpoint. Only the keeper reopening its own log sets
    /// it; a reader cannot tell them from forged entries.
    pub allow_uncovered: bool,
}

/// The result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Log.
    pub log_id: LogId,
    /// Keeper.
    pub keeper: Keeper,
    /// First sequence number in the file (after an anchor checkpoint, if any).
    pub first_seq: u64,
    /// Last sequence number.
    pub last_seq: u64,
    /// Hash of the last entry.
    pub head: EntryHash,
    /// Visible entries.
    pub entries: u64,
    /// Elided entries.
    pub elided: u64,
    /// Valid checkpoints.
    pub checkpoints: u64,
    /// Last sequence number covered by a checkpoint.
    pub last_checkpoint: u64,
    /// First entry after the last checkpoint, when `allow_uncovered` let it through.
    pub uncovered_from: Option<u64>,
    /// Known heads older than the file, hence not checked.
    pub known_unchecked: u64,
    /// Sequence number of the anchor checkpoint of a partial export: the file does not show
    /// the entries up to it. `None` when the file starts at entry 0.
    pub anchor: Option<u64>,
    /// Entries whose time is before the previous entry's: the keeper's clock stepped back.
    pub time_regressions: u64,
}

/// Parses and verifies a file.
///
/// # Errors
/// See [`verify_records`] and [`parse_file`].
pub fn verify_file(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> Result<(ParsedFile, Report), Error> {
    let parsed = parse_file(bytes)?;
    let report = verify_records(parsed.header, &parsed.records, options)?;
    Ok((parsed, report))
}

/// Verifies the records of a log.
///
/// Checks, in order: every record belongs to the log; every checkpoint is signed by the pinned
/// key; entries follow each other without gap, insertion or reordering, each linked to the
/// previous hash; every checkpoint matches the chain where it stands; the last entry is
/// covered by a checkpoint; every known head is present.
///
/// # Errors
/// [`Error::WrongLog`], [`Error::BadSignature`], [`Error::BrokenChain`],
/// [`Error::MisplacedEvent`], [`Error::CheckpointMismatch`], [`Error::NoCheckpoint`],
/// [`Error::Uncovered`], [`Error::KnownCheckpointMissing`], [`Error::EmptyLog`].
pub fn verify_records(
    header: Header,
    records: &[Record],
    options: &VerifyOptions<'_>,
) -> Result<Report, Error> {
    if header.keeper != options.keeper {
        return Err(Error::WrongLog);
    }
    let log_id = header.log_id;
    // (seq, hash) of the last record, entry, elided entry or anchor.
    let mut cur: Option<(u64, EntryHash)> = None;
    let mut anchor: Option<u64> = None;
    let mut first_seq: Option<u64> = None;
    let mut last_checkpoint: Option<u64> = None;
    let mut last_time = None;
    let mut hashes = BTreeMap::new();
    let mut report_entries = 0u64;
    let mut report_elided = 0u64;
    let mut checkpoints = 0u64;
    let mut time_regressions = 0u64;

    for record in records {
        match record {
            Record::Checkpoint(cp) => {
                if cp.log_id != log_id {
                    return Err(Error::WrongLog);
                }
                cp.verify(options.key, options.keeper)?;
                match cur {
                    None => {
                        // Anchor of a partial export: the chain resumes after it.
                        cur = Some((cp.seq, cp.head));
                        anchor = Some(cp.seq);
                        hashes.insert(cp.seq, cp.head);
                    }
                    Some((seq, hash)) => {
                        if cp.seq != seq || cp.head != hash {
                            return Err(Error::CheckpointMismatch(cp.seq));
                        }
                    }
                }
                last_checkpoint = Some(cp.seq);
                checkpoints += 1;
            }
            Record::Entry(e) => {
                if e.log_id != log_id {
                    return Err(Error::WrongLog);
                }
                let (expected_seq, expected_prev) = next_link(cur)?;
                if e.seq != expected_seq || e.prev != expected_prev {
                    return Err(Error::BrokenChain(expected_seq));
                }
                check_placement(options.keeper, e.seq, &e.event)
                    .map_err(|_| Error::MisplacedEvent(e.seq))?;
                if last_time.is_some_and(|t| e.time < t) {
                    time_regressions += 1;
                }
                last_time = Some(e.time);
                let hash = e.hash()?;
                cur = Some((e.seq, hash));
                hashes.insert(e.seq, hash);
                first_seq.get_or_insert(e.seq);
                report_entries += 1;
            }
            Record::Elided(el) => {
                let (expected_seq, expected_prev) = next_link(cur)?;
                if el.seq != expected_seq || el.prev != expected_prev {
                    return Err(Error::BrokenChain(expected_seq));
                }
                let hash = el.hash(&log_id)?;
                cur = Some((el.seq, hash));
                hashes.insert(el.seq, hash);
                first_seq.get_or_insert(el.seq);
                report_elided += 1;
            }
        }
    }

    if first_seq.is_none() {
        return Err(Error::EmptyLog);
    }
    let (last_seq, head) = cur.ok_or(Error::EmptyLog)?;
    let mut uncovered_from = None;
    match last_checkpoint {
        Some(cp) if cp == last_seq => {}
        Some(cp) if options.allow_uncovered => uncovered_from = Some(cp.saturating_add(1)),
        Some(cp) => return Err(Error::Uncovered(cp.saturating_add(1))),
        None if options.allow_uncovered => uncovered_from = Some(first_seq.unwrap_or(0)),
        None => return Err(Error::NoCheckpoint),
    }

    let oldest = anchor.or(first_seq).unwrap_or(last_seq);
    let mut known_unchecked = 0u64;
    for known in options.known {
        if known.seq < oldest {
            known_unchecked += 1;
            continue;
        }
        if hashes.get(&known.seq) != Some(&known.head) {
            return Err(Error::KnownCheckpointMissing(known.seq));
        }
    }

    Ok(Report {
        log_id,
        keeper: options.keeper,
        first_seq: first_seq.unwrap_or(0),
        last_seq,
        head,
        entries: report_entries,
        elided: report_elided,
        checkpoints,
        last_checkpoint: last_checkpoint.unwrap_or(0),
        uncovered_from,
        known_unchecked,
        anchor,
        time_regressions,
    })
}

fn next_link(cur: Option<(u64, EntryHash)>) -> Result<(u64, EntryHash), Error> {
    match cur {
        None => Ok((0, EntryHash::ZERO)),
        Some((seq, hash)) => Ok((seq.checked_add(1).ok_or(Error::Limit)?, hash)),
    }
}

/// What a reader may see of the log (`docs/roles.md`, « Voir le journal »).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// The whole log: server administrator, `Auditor` of the organisation.
    All,
    /// The events of these lockers: their owners, managers and auditors.
    Lockers(Vec<LockerId>),
}

impl Scope {
    /// Whether an event about `locker` is visible.
    #[must_use]
    pub fn admits(&self, locker: Option<LockerId>) -> bool {
        match self {
            Scope::All => true,
            Scope::Lockers(list) => locker.is_some_and(|l| list.contains(&l)),
        }
    }
}

/// The records a reader of `scope` receives: entries outside the scope are elided, so the
/// chain and the checkpoints still verify, and nothing about the hidden events leaks but their
/// number. Already elided records stay elided.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn redact(records: &[Record], scope: &Scope) -> Result<Vec<Record>, Error> {
    records
        .iter()
        .map(|r| match r {
            Record::Entry(e) if !scope.admits(e.event.locker()) => Ok(Record::Elided(e.elide()?)),
            other => Ok(other.clone()),
        })
        .collect()
}
