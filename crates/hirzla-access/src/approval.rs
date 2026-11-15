//! Multi-owner approvals (`docs/sync-protocol.md` § 7.7, `docs/roles.md` « Validation à
//! plusieurs »).
//!
//! An approval is a device signature over an `ApprovalRequest`, joined to the operation before
//! it is published. Actions 1 to 3 are checked by every device while computing the
//! authorisation state ([`crate::authz`]). Action 4, exporting a locker, is a local gate:
//! [`check_local_quorum`].

use std::collections::BTreeSet;

use hirzla_crypto::sign::{DeviceDomain, DeviceSigningKey, Domain, Signature, VerifyingKey};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16};

use crate::control::Approval;
use crate::{AccessError, Denial};

/// The actions that take approvals (`ApprovalRequest.action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveAction {
    /// 1: remove an `Owner`.
    OwnerRemoval,
    /// 2: change the role of an `Owner`.
    OwnerRoleChange,
    /// 3: change the quorum.
    Policy,
    /// 4: export a locker (local gate, ADR 0020).
    LockerExport,
}

impl SensitiveAction {
    /// Code on the wire.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            SensitiveAction::OwnerRemoval => 1,
            SensitiveAction::OwnerRoleChange => 2,
            SensitiveAction::Policy => 3,
            SensitiveAction::LockerExport => 4,
        }
    }
}

/// What an approver signs (`sync-protocol.md` § 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Locker.
    pub locker_id: Id16,
    /// Random identifier drawn by the initiator, equal to the operation's.
    pub request_id: Id16,
    /// Action.
    pub action: SensitiveAction,
    /// Member targeted (actions 1 and 2).
    pub target: Option<Id16>,
    /// New role code (action 2) or new quorum (action 3).
    pub detail: Option<u64>,
    /// Member who publishes the operation.
    pub issuer: Id16,
    /// Approving member.
    pub approver_member: Id16,
    /// Approving device.
    pub approver_device: Id16,
}

impl ApprovalRequest {
    /// Canonical encoding: the bytes signed after `"hirzla/v1/approval" ‖ 0x00`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        let mut e = vec![
            (1, Value::bytes(&self.locker_id)),
            (2, Value::bytes(&self.request_id)),
            (3, Value::Uint(self.action.code())),
        ];
        if let Some(t) = &self.target {
            e.push((4, Value::bytes(t)));
        }
        if let Some(d) = self.detail {
            e.push((5, Value::Uint(d)));
        }
        e.push((6, Value::bytes(&self.issuer)));
        e.push((7, Value::bytes(&self.approver_member)));
        e.push((8, Value::bytes(&self.approver_device)));
        Ok(cbor::encode(&Value::map(e))?.to_vec())
    }

    /// Signs the request with the approver's device key.
    ///
    /// # Errors
    /// [`AccessError::Crypto`] or [`AccessError::Malformed`].
    pub fn approve(&self, device_key: &DeviceSigningKey) -> Result<Approval, AccessError> {
        let sig = device_key
            .sign(DeviceDomain::Approval, &self.encode()?)
            .map_err(|_| AccessError::Crypto)?;
        Ok(Approval {
            member: self.approver_member,
            device: self.approver_device,
            sig: sig.as_bytes().to_vec(),
        })
    }

    /// The same request seen from another approver.
    #[must_use]
    pub fn for_approver(&self, member: Id16, device: Id16) -> ApprovalRequest {
        ApprovalRequest {
            approver_member: member,
            approver_device: device,
            ..self.clone()
        }
    }
}

/// Verifies one approval against the request it should sign and the approver's certificate.
///
/// # Errors
/// [`AccessError::Denied`] with [`Denial::InvalidApproval`].
pub fn verify_approval(
    approval: &Approval,
    request: &ApprovalRequest,
    approver_cert: &DeviceCert,
) -> Result<(), AccessError> {
    let bad = AccessError::Denied(Denial::InvalidApproval);
    if approval.member != request.approver_member
        || approval.device != request.approver_device
        || approver_cert.member != approval.member
        || approver_cert.device != approval.device
    {
        return Err(bad);
    }
    let key = VerifyingKey::from_bytes(&approver_cert.sig).map_err(|_| bad)?;
    let sig = Signature::from_bytes(&approval.sig).map_err(|_| bad)?;
    key.verify(Domain::Approval, &request.encode()?, &sig)
        .map_err(|_| bad)
}

/// Local gate for action 4 (export a locker): at least `quorum` distinct owners among the
/// requester (if owner) and valid approvers.
///
/// `owners` lists the owners of the locker with the certificate of each active device, as the
/// authorisation state gives them ([`crate::authz::LockerState::owner_devices`]).
///
/// # Errors
/// [`AccessError::Denied`] with [`Denial::InvalidApproval`], [`Denial::RequestId`] or
/// [`Denial::QuorumNotMet`].
pub fn check_local_quorum(
    locker_id: Id16,
    request_id: Id16,
    requester: Id16,
    approvals: &[Approval],
    owners: &[(Id16, Vec<DeviceCert>)],
    quorum: u8,
) -> Result<(), AccessError> {
    let base = ApprovalRequest {
        locker_id,
        request_id,
        action: SensitiveAction::LockerExport,
        target: None,
        detail: None,
        issuer: requester,
        approver_member: requester,
        approver_device: [0; 16],
    };
    let mut counted: BTreeSet<Id16> = BTreeSet::new();
    if owners.iter().any(|(m, _)| *m == requester) {
        counted.insert(requester);
    }
    for a in approvals {
        let cert = owners
            .iter()
            .find(|(m, _)| *m == a.member)
            .and_then(|(_, certs)| certs.iter().find(|c| c.device == a.device))
            .ok_or(AccessError::Denied(Denial::InvalidApproval))?;
        verify_approval(a, &base.for_approver(a.member, a.device), cert)?;
        if !counted.insert(a.member) {
            return Err(AccessError::Denied(Denial::InvalidApproval));
        }
    }
    if counted.len() >= usize::from(quorum) {
        Ok(())
    } else {
        Err(AccessError::Denied(Denial::QuorumNotMet))
    }
}
