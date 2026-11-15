//! Frozen encodings of `hirzla-access` (`tests/vectors/access-encodings-v1.txt`): control
//! bodies 12 to 34, the signed `ApprovalRequest`, key log entries, the signed bytes of a key log
//! head and a `keylog_proof`. A change to any of these bytes is a format change (ADR needed).
//!
//! Short encodings are frozen byte for byte (`hex`), long ones by length and SHA-384.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod common;

use common::{records, to_hex};
use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::control::{
    Approval, ControlBody, DeviceRevocation, EpochWrap, GroupBind, GroupPut, Policy, Revoke,
    Rotate, SecretRole,
};
use hirzla_access::keylog::{EntryKind, InclusionItem, KeyLogEntry, KeyLogHead, KeyLogProof};
use hirzla_access::role::SecretWrite;
use hirzla_access::Role;
use hirzla_crypto::util::sha384;
use hirzla_vault::model::{KeyEnvelopeEntry, OpRef};

const HEX_MAX: usize = 200;

fn head() -> KeyLogHead {
    KeyLogHead {
        log_id: [0x10; 16],
        size: 6,
        root: [0x22; 48],
        time_ms: 1_700_000_000_123,
        sig: vec![0x33; 4725],
    }
}

fn entry(kind: EntryKind) -> KeyLogEntry {
    KeyLogEntry {
        kind,
        member: [0xA1; 16],
        device: matches!(kind, EntryKind::DeviceCert | EntryKind::DeviceRevocation)
            .then_some([0xD1; 16]),
        locker: (kind == EntryKind::LockerRevoke).then_some([0x1C; 16]),
        object: [0x44; 48],
        logged_ms: 1_700_000_000_000,
    }
}

fn opref() -> OpRef {
    OpRef {
        member: [0xA1; 16],
        device: [0xD1; 16],
        seq: 7,
    }
}

fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let approval = Approval {
        member: [0xA2; 16],
        device: [0xD2; 16],
        sig: vec![0x55; 4725],
    };
    let envelope = KeyEnvelopeEntry {
        member: [0xA1; 16],
        device: [0xD1; 16],
        recipient_key: [0x66; 48],
        envelope: vec![0x5A; 1707],
    };
    let body = |b: ControlBody| b.encode().unwrap();
    vec![
        (
            "revoke",
            body(ControlBody::Revoke(Revoke {
                member: [0xA3; 16],
                envelopes: vec![envelope.clone()],
                prev: vec![EpochWrap {
                    epoch: opref(),
                    wrap: [0x77; 40],
                }],
                request_id: Some([0x88; 16]),
                approvals: Some(vec![approval.clone()]),
            })),
        ),
        (
            "rotate",
            body(ControlBody::Rotate(Rotate {
                envelopes: vec![],
                prev: vec![EpochWrap {
                    epoch: opref(),
                    wrap: [0x77; 40],
                }],
            })),
        ),
        ("envelope-add-empty", body(ControlBody::EnvelopeAdd(vec![]))),
        (
            "quarantine-accept",
            body(ControlBody::QuarantineAccept(vec![[0x01; 48]])),
        ),
        (
            "quarantine-reject",
            body(ControlBody::QuarantineReject {
                ops: vec![[0x02; 48]],
                auto: true,
            }),
        ),
        (
            "compact",
            body(ControlBody::Compact(vec![[0x04; 48], [0x03; 48]])),
        ),
        (
            "policy",
            body(ControlBody::Policy(Policy {
                owner_removal_quorum: 3,
                request_id: [0x88; 16],
                approvals: vec![approval],
            })),
        ),
        (
            "group-put",
            body(ControlBody::GroupPut(GroupPut {
                group: [0x99; 16],
                members: vec![[0xA2; 16], [0xA1; 16]],
            })),
        ),
        (
            "group-bind",
            body(ControlBody::GroupBind(GroupBind {
                group: [0x99; 16],
                role: Some(Role::Editor),
            })),
        ),
        (
            "group-bind-remove",
            body(ControlBody::GroupBind(GroupBind {
                group: [0x99; 16],
                role: None,
            })),
        ),
        (
            "secret-role",
            body(ControlBody::SecretRole(SecretRole {
                secret: [0x5E; 16],
                member: [0xA2; 16],
                role: Some(SecretWrite::Reader),
            })),
        ),
        ("checkpoint", body(ControlBody::Checkpoint(head()))),
        (
            "approval-request-owner-removal",
            ApprovalRequest {
                locker_id: [0x1C; 16],
                request_id: [0x88; 16],
                action: SensitiveAction::OwnerRemoval,
                target: Some([0xA3; 16]),
                detail: None,
                issuer: [0xA1; 16],
                approver_member: [0xA2; 16],
                approver_device: [0xD2; 16],
            }
            .encode()
            .unwrap(),
        ),
        (
            "approval-request-policy",
            ApprovalRequest {
                locker_id: [0x1C; 16],
                request_id: [0x88; 16],
                action: SensitiveAction::Policy,
                target: None,
                detail: Some(3),
                issuer: [0xA1; 16],
                approver_member: [0xA2; 16],
                approver_device: [0xD2; 16],
            }
            .encode()
            .unwrap(),
        ),
        (
            "approval-request-export",
            ApprovalRequest {
                locker_id: [0x1C; 16],
                request_id: [0x88; 16],
                action: SensitiveAction::LockerExport,
                target: None,
                detail: None,
                issuer: [0xA1; 16],
                approver_member: [0xA2; 16],
                approver_device: [0xD2; 16],
            }
            .encode()
            .unwrap(),
        ),
        (
            "device-revocation-body",
            DeviceRevocation {
                member: [0xA1; 16],
                device: [0xD1; 16],
                revoked_ms: 1_700_000_000_001,
                issuer_sig: vec![],
            }
            .body()
            .unwrap(),
        ),
        (
            "keylog-entry-member-key",
            entry(EntryKind::MemberKey).encode().unwrap(),
        ),
        (
            "keylog-entry-device-cert",
            entry(EntryKind::DeviceCert).encode().unwrap(),
        ),
        (
            "keylog-entry-device-revocation",
            entry(EntryKind::DeviceRevocation).encode().unwrap(),
        ),
        (
            "keylog-entry-locker-revoke",
            entry(EntryKind::LockerRevoke).encode().unwrap(),
        ),
        (
            "keylog-leaf-hash-member-key",
            entry(EntryKind::MemberKey).leaf_hash().unwrap().to_vec(),
        ),
        ("keylog-head-signed-bytes", head().signed_bytes().unwrap()),
        ("keylog-head", head().encode().unwrap()),
        (
            "keylog-proof",
            KeyLogProof {
                head: head(),
                items: vec![InclusionItem {
                    index: 5,
                    entry: entry(EntryKind::DeviceCert),
                    path: vec![[0x01; 48], [0x02; 48]],
                }],
            }
            .encode()
            .unwrap(),
        ),
    ]
}

fn render(name: &str, bytes: &[u8]) -> String {
    if bytes.len() <= HEX_MAX {
        format!("name = {name}\nhex = {}\n", to_hex(bytes))
    } else {
        format!(
            "name = {name}\nlen = {}\nsha384 = {}\n",
            bytes.len(),
            to_hex(&sha384(bytes))
        )
    }
}

#[test]
fn encodings_are_frozen() {
    let frozen = records(include_str!("vectors/access-encodings-v1.txt"));
    let cases = cases();
    assert_eq!(frozen.len(), cases.len(), "one record per case");
    for (r, (name, bytes)) in frozen.iter().zip(&cases) {
        assert_eq!(r["name"], *name);
        if let Some(h) = r.get("hex") {
            assert_eq!(&to_hex(bytes), h, "{name}");
        } else {
            assert_eq!(r["len"].parse::<usize>().unwrap(), bytes.len(), "{name}");
            assert_eq!(&to_hex(&sha384(bytes)), &r["sha384"], "{name}");
        }
    }
}

#[test]
fn frozen_bodies_decode_back() {
    for (name, bytes) in cases() {
        if name.starts_with("approval") || name.starts_with("keylog") || name.starts_with("device")
        {
            continue;
        }
        let back = ControlBody::decode(&bytes).unwrap();
        assert_eq!(back.encode().unwrap(), bytes, "{name}");
    }
}

/// Prints the vector file; used once to freeze it, then the output is reviewed by hand.
#[test]
#[ignore = "generator"]
fn print_vectors() {
    let mut out = String::from(
        "# Frozen encodings of hirzla-access, format v1 (see tests/vectors.rs).\n\
         # hex: the exact bytes; len + sha384: long encodings.\n",
    );
    for (name, bytes) in cases() {
        out.push('\n');
        out.push_str(&render(name, &bytes));
    }
    print!("{out}");
}
