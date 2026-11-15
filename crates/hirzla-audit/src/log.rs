//! The emission API: a log kept in an append-only file by its keeper
//! (`docs/evenements.md` § 7).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::chain::{Chain, Checkpoint, CheckpointSigner, Record};
use crate::event::Event;
use crate::field::{Count, EntryHash, LogId};
use crate::time::Timestamp;
use crate::verify::{parse_file_lenient, verify_records, Header, VerifyOptions};
use crate::Error;

/// Anything that records audit events: what `hirzla-core` and `hirzlad` call.
pub trait AuditEmitter {
    /// Records `event` now and returns its sequence number.
    ///
    /// # Errors
    /// The implementation's errors; an event that cannot be recorded must not be lost
    /// silently: the caller refuses the audited action or raises an alarm.
    fn emit(&mut self, event: Event) -> Result<u64, Error>;
}

/// When the log signs checkpoints by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// Sign a checkpoint after this many entries (at least 1).
    pub every_entries: u64,
    /// Flush every record to disk before returning (`sync_data`).
    pub sync_each_record: bool,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        CheckpointPolicy {
            every_entries: 64,
            sync_each_record: true,
        }
    }
}

/// A log file written by its keeper.
///
/// One writer per file; wrap it in a mutex to share it. If a write fails, the log refuses
/// any further call: reopen it with [`AuditLog::open`], which checks it and cuts a torn
/// record.
pub struct AuditLog<S: CheckpointSigner> {
    chain: Chain,
    signer: S,
    file: File,
    policy: CheckpointPolicy,
    since_checkpoint: u64,
    poisoned: bool,
}

impl<S: CheckpointSigner> AuditLog<S> {
    /// Creates a new log at `path`, which must not exist. Writes the header, a
    /// [`Event::LogStarted`] entry and a first checkpoint.
    ///
    /// `previous` links this log to the last head of the log it replaces, if any.
    ///
    /// # Errors
    /// [`Error::Io`] (the file exists, among others), [`Error::InvalidConfig`] on a zero
    /// policy, [`Error::Crypto`].
    pub fn create(
        path: &Path,
        signer: S,
        policy: CheckpointPolicy,
        previous: Option<(LogId, EntryHash)>,
    ) -> Result<Self, Error> {
        check_policy(policy)?;
        let log_id = LogId::random()?;
        let header = Header {
            log_id,
            keeper: signer.keeper(),
        };
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&header.to_bytes()?)?;
        let mut log = AuditLog {
            chain: Chain::new(log_id, signer.keeper()),
            signer,
            file,
            policy,
            since_checkpoint: 0,
            poisoned: false,
        };
        log.emit_at(
            Timestamp::now(),
            Event::LogStarted {
                previous_log: previous.map(|p| p.0),
                previous_head: previous.map(|p| p.1),
            },
        )?;
        log.checkpoint()?;
        Ok(log)
    }

    /// Opens an existing log, verifies it with the signer's own key, cuts an incomplete
    /// trailing record left by a crash, then records [`Event::LogResumed`] and a checkpoint.
    ///
    /// Entries after the last checkpoint are accepted here (a crash may have stopped the log
    /// before it signed); they are covered by the new checkpoint, and their number is recorded
    /// in [`Event::LogResumed`] so that entries injected while the keeper was stopped stay
    /// visible. A site that cannot accept this sets `every_entries` to 1.
    ///
    /// # Errors
    /// Any verification error of [`verify_records`]; [`Error::WrongLog`] if the file belongs
    /// to another keeper; [`Error::Io`].
    pub fn open(path: &Path, signer: S, policy: CheckpointPolicy) -> Result<Self, Error> {
        check_policy(policy)?;
        let bytes = std::fs::read(path)?;
        let parsed = parse_file_lenient(&bytes)?;
        let report = verify_records(
            parsed.header,
            &parsed.records,
            &VerifyOptions {
                key: signer.verifying_key(),
                keeper: signer.keeper(),
                known: &[],
                allow_uncovered: true,
            },
        )?;
        if parsed.torn_tail {
            let len = u64::try_from(parsed.complete_len).map_err(|_| Error::Limit)?;
            let truncate = OpenOptions::new().write(true).open(path)?;
            truncate.set_len(len)?;
            truncate.sync_all()?;
        }
        let file = OpenOptions::new().append(true).open(path)?;
        let mut log = AuditLog {
            chain: Chain::resume(
                parsed.header.log_id,
                parsed.header.keeper,
                report.last_seq,
                report.head,
            ),
            signer,
            file,
            policy,
            since_checkpoint: 0,
            poisoned: false,
        };
        log.emit_at(
            Timestamp::now(),
            Event::LogResumed {
                torn_tail: parsed.torn_tail,
                uncovered: Count(
                    report
                        .uncovered_from
                        .map_or(0, |from| report.last_seq + 1 - from),
                ),
            },
        )?;
        log.checkpoint()?;
        Ok(log)
    }

    /// Log identifier.
    #[must_use]
    pub fn log_id(&self) -> LogId {
        self.chain.log_id()
    }

    /// Sequence number and hash of the last entry.
    #[must_use]
    pub fn head(&self) -> (u64, EntryHash) {
        (self.chain.last_seq().unwrap_or(0), self.chain.head())
    }

    /// Records `event` at `time`. Signs a checkpoint when the policy says so.
    ///
    /// # Errors
    /// [`Error::InvalidState`] on a misplaced event or a poisoned log, [`Error::Io`],
    /// [`Error::Crypto`].
    pub fn emit_at(&mut self, time: Timestamp, event: Event) -> Result<u64, Error> {
        if self.poisoned {
            return Err(Error::InvalidState);
        }
        let mut next = self.chain.clone();
        let entry = next.append(time, event)?;
        let seq = entry.seq;
        self.write(&Record::Entry(entry))?;
        self.chain = next;
        self.since_checkpoint += 1;
        if self.since_checkpoint >= self.policy.every_entries {
            self.checkpoint()?;
        }
        Ok(seq)
    }

    /// Signs and writes a checkpoint of the current head, and returns it: hand it to the
    /// SIEM, it lets anyone detect a later truncation.
    ///
    /// # Errors
    /// [`Error::InvalidState`] on a poisoned log, [`Error::Io`], [`Error::Crypto`].
    pub fn checkpoint(&mut self) -> Result<Checkpoint, Error> {
        if self.poisoned {
            return Err(Error::InvalidState);
        }
        let cp = self.chain.checkpoint(&self.signer, Timestamp::now())?;
        self.write(&Record::Checkpoint(cp.clone()))?;
        self.since_checkpoint = 0;
        Ok(cp)
    }

    fn write(&mut self, record: &Record) -> Result<(), Error> {
        let bytes = record.to_bytes()?;
        let result = self.file.write_all(&bytes).and_then(|()| {
            if self.policy.sync_each_record {
                self.file.sync_data()
            } else {
                Ok(())
            }
        });
        if result.is_err() {
            self.poisoned = true;
        }
        Ok(result?)
    }
}

impl<S: CheckpointSigner> AuditEmitter for AuditLog<S> {
    fn emit(&mut self, event: Event) -> Result<u64, Error> {
        self.emit_at(Timestamp::now(), event)
    }
}

fn check_policy(policy: CheckpointPolicy) -> Result<(), Error> {
    if policy.every_entries == 0 {
        Err(Error::InvalidConfig)
    } else {
        Ok(())
    }
}
