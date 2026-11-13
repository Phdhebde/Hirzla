//! Roles, signed grants and key transparency.
//!
//! A role is a key: holding a role means holding a wrapped locker key (read)
//! or a signing key the peers accept (write, share, manage). See `docs/roles.md`
//! and ADRs 0004 and 0008.

#![forbid(unsafe_code)]

/// Roles a member can hold on a locker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Reads, writes, shares and manages roles.
    Owner,
    /// Reads, writes and shares.
    Manager,
    /// Reads and writes.
    Editor,
    /// Reads only.
    Reader,
    /// Never sees the value; a bastion uses it on the member's behalf.
    BlindUser,
    /// Reads the audit log, never a secret value.
    Auditor,
}
