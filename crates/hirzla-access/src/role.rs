//! Roles and what they allow, at the three levels of `docs/roles.md`.
//!
//! This module is the table of `docs/roles.md`, nothing more. The rules that depend on the
//! history of a locker (seniority, quorum, last owner, epochs) are in [`crate::authz`].

/// Roles a member can hold on a locker (`docs/sync-protocol.md` § 7.1 for the codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Every role, in code order.
pub const ALL_ROLES: [Role; 6] = [
    Role::Owner,
    Role::Manager,
    Role::Editor,
    Role::Reader,
    Role::BlindUser,
    Role::Auditor,
];

/// A capability of the table of `docs/roles.md`, at the locker level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Hold the locker key (an envelope for one's devices).
    Read,
    /// Emit data operations.
    Write,
    /// Grant `Editor`, `Reader`, `BlindUser` or `Auditor` to a new member.
    Share,
    /// Change an existing role, remove a member, set the quorum.
    ManageRoles,
    /// Rotate the locker key, repair an envelope, compact the journal.
    RotateKey,
    /// See the journal of the locker (without values for `Auditor`).
    ViewLog,
}

/// A capability at the organisation level: roles held in the organisation locker
/// (`docs/roles.md`, « Trois niveaux », ADR 0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgCapability {
    /// Grant or change roles in the organisation locker.
    ManageOrgRoles,
    /// Define groups (`GroupPut`).
    ManageGroups,
    /// See the journal of every locker of the organisation, without values.
    ViewOrgAudit,
}

impl Role {
    /// Code of the role on the wire.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Role::Owner => 1,
            Role::Manager => 2,
            Role::Editor => 3,
            Role::Reader => 4,
            Role::BlindUser => 5,
            Role::Auditor => 6,
        }
    }

    /// Role of a wire code.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Role> {
        match code {
            1 => Some(Role::Owner),
            2 => Some(Role::Manager),
            3 => Some(Role::Editor),
            4 => Some(Role::Reader),
            5 => Some(Role::BlindUser),
            6 => Some(Role::Auditor),
            _ => None,
        }
    }

    /// Whether the role reads, so holds the locker key.
    #[must_use]
    pub const fn is_reader(self) -> bool {
        matches!(
            self,
            Role::Owner | Role::Manager | Role::Editor | Role::Reader
        )
    }

    /// Whether the role emits data operations.
    #[must_use]
    pub const fn writes(self) -> bool {
        matches!(self, Role::Owner | Role::Manager | Role::Editor)
    }

    /// The table of `docs/roles.md`.
    #[must_use]
    pub const fn has(self, capability: Capability) -> bool {
        match capability {
            Capability::Read => self.is_reader(),
            Capability::Write | Capability::RotateKey => self.writes(),
            Capability::Share => matches!(self, Role::Owner | Role::Manager),
            Capability::ManageRoles => matches!(self, Role::Owner),
            Capability::ViewLog => matches!(self, Role::Owner | Role::Manager | Role::Auditor),
        }
    }

    /// Whether this role may grant `granted` to a new member (`sync-protocol.md` § 7.3).
    #[must_use]
    pub const fn may_grant(self, granted: Role) -> bool {
        match self {
            Role::Owner => true,
            Role::Manager => !matches!(granted, Role::Owner | Role::Manager),
            _ => false,
        }
    }

    /// Organisation-level capabilities of a role held in the organisation locker.
    #[must_use]
    pub const fn has_org(self, capability: OrgCapability) -> bool {
        match capability {
            OrgCapability::ManageOrgRoles => matches!(self, Role::Owner),
            OrgCapability::ManageGroups => matches!(self, Role::Owner | Role::Manager),
            OrgCapability::ViewOrgAudit => matches!(self, Role::Owner | Role::Auditor),
        }
    }
}

/// A secret-level write override (`SecretRole`, `docs/roles.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretWrite {
    /// The member may write this secret, even as a locker `Reader`.
    Editor,
    /// The member may not write this secret, even as a locker `Editor` or `Manager`.
    Reader,
}

impl SecretWrite {
    /// Code on the wire (the role code it borrows).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            SecretWrite::Editor => 3,
            SecretWrite::Reader => 4,
        }
    }

    /// Override of a wire code; 0 means « no override » and is handled by the caller.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<SecretWrite> {
        match code {
            3 => Some(SecretWrite::Editor),
            4 => Some(SecretWrite::Reader),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_unknown_codes_are_refused() {
        for r in ALL_ROLES {
            assert_eq!(Role::from_code(r.code()), Some(r));
        }
        for bad in [0, 7, 30, u64::MAX] {
            assert_eq!(Role::from_code(bad), None);
        }
        assert_eq!(SecretWrite::from_code(0), None);
        assert_eq!(SecretWrite::from_code(1), None);
        assert_eq!(SecretWrite::from_code(5), None);
    }

    /// The table of `docs/roles.md`, row by row.
    #[test]
    fn capability_table_matches_roles_md() {
        use Capability::*;
        let table: [(Role, [bool; 6]); 6] = [
            (Role::Owner, [true, true, true, true, true, true]),
            (Role::Manager, [true, true, true, false, true, true]),
            (Role::Editor, [true, true, false, false, true, false]),
            (Role::Reader, [true, false, false, false, false, false]),
            (Role::BlindUser, [false, false, false, false, false, false]),
            (Role::Auditor, [false, false, false, false, false, true]),
        ];
        for (role, row) in table {
            for (cap, expected) in [Read, Write, Share, ManageRoles, RotateKey, ViewLog]
                .into_iter()
                .zip(row)
            {
                assert_eq!(role.has(cap), expected, "{role:?} {cap:?}");
            }
        }
    }

    #[test]
    fn only_owner_grants_owner_and_manager() {
        for granter in ALL_ROLES {
            for granted in ALL_ROLES {
                let expected = match granter {
                    Role::Owner => true,
                    Role::Manager => !matches!(granted, Role::Owner | Role::Manager),
                    _ => false,
                };
                assert_eq!(
                    granter.may_grant(granted),
                    expected,
                    "{granter:?} {granted:?}"
                );
            }
        }
    }

    #[test]
    fn organisation_capabilities() {
        use OrgCapability::*;
        for r in ALL_ROLES {
            assert_eq!(r.has_org(ManageOrgRoles), r == Role::Owner);
            assert_eq!(
                r.has_org(ManageGroups),
                matches!(r, Role::Owner | Role::Manager)
            );
            assert_eq!(
                r.has_org(ViewOrgAudit),
                matches!(r, Role::Owner | Role::Auditor)
            );
        }
    }
}
