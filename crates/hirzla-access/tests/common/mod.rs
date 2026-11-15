//! Test harness: members with real hybrid keys, and a simulated locker journal that emits
//! control and data operations with explicit causality.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::authz::{
    compute, AuthzState, ControlOp, ControlStatus, Dag, DataOp, DataStatus, DataTarget,
    LockerContext, LockerState,
};
use hirzla_access::control::{
    key_id, Approval, ControlBody, DeviceRemove, DeviceRevocation, EpochWrap, Grant, LockerCreate,
    Revoke, Rotate,
};
use hirzla_access::Role;
use hirzla_crypto::kem;
use hirzla_crypto::sign::{DeviceSigningKey, MemberSigningKey};
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16, KeyEnvelopeEntry, MemberKeys, OpId, OpRef};

/// One device with its keys.
pub struct Dev {
    pub member: Id16,
    pub device: Id16,
    pub cert: DeviceCert,
    pub sign: DeviceSigningKey,
    pub kem: kem::PrivateKey,
}

/// One member with its root key and devices.
pub struct Person {
    pub keys: MemberKeys,
    pub key: MemberSigningKey,
    pub devs: Vec<Dev>,
}

pub fn member_id(n: u8) -> Id16 {
    let mut id = [0u8; 16];
    id[0] = 0xA0;
    id[1] = n;
    id
}

pub fn device_id(n: u8, k: u8) -> Id16 {
    let mut id = [0u8; 16];
    id[0] = 0xD0;
    id[1] = n;
    id[2] = k;
    id
}

/// Certifies a device of `keys` with `key`.
pub fn certify(keys: &MemberKeys, key: &MemberSigningKey, device: Id16) -> Dev {
    let sign = DeviceSigningKey::generate().unwrap();
    let kem = kem::PrivateKey::generate().unwrap();
    let mut cert = DeviceCert {
        member: keys.member,
        device,
        sig: sign.verifying_key().as_bytes().to_vec(),
        kem: kem.public_key().as_bytes().to_vec(),
        issued_ms: 1_700_000_000_000,
        issuer_sig: Vec::new(),
    };
    cert.issuer_sig = key
        .certify_device(&cert.body().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    Dev {
        member: keys.member,
        device,
        cert,
        sign,
        kem,
    }
}

impl Person {
    pub fn new(n: u8, devices: u8) -> Person {
        let key = MemberSigningKey::generate().unwrap();
        let keys = MemberKeys {
            member: member_id(n),
            sig: key.verifying_key().as_bytes().to_vec(),
        };
        let devs = (0..devices)
            .map(|k| certify(&keys, &key, device_id(n, k)))
            .collect();
        Person { keys, key, devs }
    }

    pub fn id(&self) -> Id16 {
        self.keys.member
    }

    pub fn dev(&self) -> &Dev {
        &self.devs[0]
    }

    pub fn certs(&self) -> Vec<DeviceCert> {
        self.devs.iter().map(|d| d.cert.clone()).collect()
    }

    /// A revocation of `device`, signed by the member key.
    pub fn revoke(&self, device: Id16) -> DeviceRevocation {
        let mut r = DeviceRevocation {
            member: self.id(),
            device,
            revoked_ms: 1_700_000_000_001,
            issuer_sig: Vec::new(),
        };
        r.issuer_sig = self
            .key
            .revoke_device(&r.body().unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
        r
    }
}

/// An envelope entry for `cert` (its content is not checked by the authorisation rules).
pub fn env_for(cert: &DeviceCert) -> KeyEnvelopeEntry {
    KeyEnvelopeEntry {
        member: cert.member,
        device: cert.device,
        recipient_key: key_id(&cert.kem),
        envelope: vec![0x5A; 1707],
    }
}

pub fn envs(certs: &[DeviceCert]) -> Vec<KeyEnvelopeEntry> {
    certs.iter().map(env_for).collect()
}

/// A simulated locker journal.
#[derive(Clone)]
pub struct Sim {
    pub locker: Id16,
    pub genesis: OpId,
    pub control: Vec<ControlOp>,
    pub data: Vec<DataOp>,
    /// Every node with its deps and lamport, data included.
    pub nodes: BTreeMap<OpId, (Vec<OpId>, u64)>,
    /// Last `(seq, op_id)` per device.
    pub chains: BTreeMap<(Id16, Id16), (u64, OpId)>,
    pub counter: u64,
}

/// What to depend on.
#[derive(Clone)]
pub enum Deps {
    /// Every current head (online author).
    Heads,
    /// Exactly these (plus the author's `prev`): an author that has not seen the rest.
    Only(Vec<OpId>),
}

impl Sim {
    pub fn locker_id() -> Id16 {
        [0x1C; 16]
    }

    pub fn create(owner: &Person, personal: bool) -> Sim {
        let dev = owner.dev();
        let opref = OpRef {
            member: dev.member,
            device: dev.device,
            seq: 1,
        };
        let body = ControlBody::LockerCreate(LockerCreate {
            creator: owner.keys.clone(),
            creator_device: dev.cert.clone(),
            envelope: env_for(&dev.cert),
            personal,
            keylog_proof: None,
        });
        let op_id = fake_op_id(&Self::locker_id(), &opref, &body.encode().unwrap(), &[]);
        let op = ControlOp {
            op_id,
            locker_id: Self::locker_id(),
            opref,
            lamport: 1,
            epoch: opref,
            deps: Vec::new(),
            body,
        };
        let mut sim = Sim {
            locker: Self::locker_id(),
            genesis: op_id,
            control: vec![op],
            data: Vec::new(),
            nodes: BTreeMap::new(),
            chains: BTreeMap::new(),
            counter: 0,
        };
        sim.nodes.insert(op_id, (Vec::new(), 1));
        sim.chains.insert((dev.member, dev.device), (1, op_id));
        sim
    }

    pub fn ctx(&self) -> LockerContext {
        LockerContext {
            locker_id: self.locker,
            genesis: self.genesis,
        }
    }

    pub fn dag(&self) -> Dag {
        Dag::new(self.nodes.iter().map(|(id, (d, _))| (*id, d.as_slice())))
    }

    pub fn compute(&self) -> AuthzState {
        compute(&self.ctx(), &self.control, &self.dag())
    }

    pub fn heads(&self) -> Vec<OpId> {
        let cited: BTreeSet<OpId> = self.nodes.values().flat_map(|(d, _)| d.clone()).collect();
        self.nodes
            .keys()
            .filter(|id| !cited.contains(*id))
            .copied()
            .collect()
    }

    fn resolve_deps(&self, author: &Dev, deps: &Deps) -> (Vec<OpId>, u64, u64) {
        let prev = self.chains.get(&(author.member, author.device)).copied();
        let mut d: BTreeSet<OpId> = match deps {
            Deps::Heads => self.heads().into_iter().collect(),
            Deps::Only(v) => v.iter().copied().collect(),
        };
        if let Some((_, p)) = prev {
            d.insert(p);
        }
        let lamport = 1 + d.iter().map(|x| self.nodes[x].1).max().unwrap_or(0);
        let seq = prev.map_or(1, |(s, _)| s + 1);
        (d.into_iter().collect(), lamport, seq)
    }

    /// The state an author sees with these deps: `S(A ∩ past)`.
    pub fn view(&self, deps: &[OpId]) -> LockerState {
        let dag = self.dag();
        let state = self.compute();
        let deps = deps.to_vec();
        state
            .state_before(&|id| deps.contains(id) || deps.iter().any(|d| dag_precedes(&dag, id, d)))
    }

    /// Emits a control operation; `epoch` defaults to the right one for the author's view.
    pub fn emit_with(
        &mut self,
        author: &Dev,
        deps: Deps,
        build: impl FnOnce(&LockerState, OpRef) -> ControlBody,
        epoch: Option<OpRef>,
    ) -> OpId {
        let (d, lamport, seq) = self.resolve_deps(author, &deps);
        let view = self.view(&d);
        let opref = OpRef {
            member: author.member,
            device: author.device,
            seq,
        };
        let body = build(&view, opref);
        let epoch = epoch.unwrap_or_else(|| {
            if body.creates_epoch() {
                opref
            } else {
                view.current_epoch().unwrap_or(opref)
            }
        });
        let op_id = fake_op_id(&self.locker, &opref, &body.encode().unwrap(), &d);
        self.nodes.insert(op_id, (d.clone(), lamport));
        self.chains
            .insert((author.member, author.device), (seq, op_id));
        self.control.push(ControlOp {
            op_id,
            locker_id: self.locker,
            opref,
            lamport,
            epoch,
            deps: d,
            body,
        });
        op_id
    }

    pub fn emit(
        &mut self,
        author: &Dev,
        build: impl FnOnce(&LockerState, OpRef) -> ControlBody,
    ) -> OpId {
        self.emit_with(author, Deps::Heads, build, None)
    }

    pub fn emit_after(
        &mut self,
        author: &Dev,
        deps: Vec<OpId>,
        build: impl FnOnce(&LockerState, OpRef) -> ControlBody,
    ) -> OpId {
        self.emit_with(author, Deps::Only(deps), build, None)
    }

    /// Emits a data operation.
    pub fn write_with(&mut self, author: &Dev, deps: Deps, target: DataTarget) -> DataOp {
        let (d, lamport, seq) = self.resolve_deps(author, &deps);
        let view = self.view(&d);
        let opref = OpRef {
            member: author.member,
            device: author.device,
            seq,
        };
        self.counter += 1;
        let op_id = fake_op_id(&self.locker, &opref, &self.counter.to_be_bytes(), &d);
        let epoch = view.current_epoch().unwrap_or(opref);
        self.nodes.insert(op_id, (d, lamport));
        self.chains
            .insert((author.member, author.device), (seq, op_id));
        let op = DataOp {
            op_id,
            opref,
            epoch,
            target,
        };
        self.data.push(op);
        op
    }

    pub fn write(&mut self, author: &Dev) -> DataOp {
        self.write_with(author, Deps::Heads, DataTarget::Secret(SECRET))
    }

    pub fn status(&self, op: &OpId) -> ControlStatus {
        self.compute().status(op).unwrap()
    }

    pub fn data_status(&self, op: &DataOp) -> DataStatus {
        self.compute().classify_data(op, &self.dag())
    }

    // ----- body builders, from the author's view -----

    pub fn grant(&mut self, author: &Dev, who: &Person, role: Role) -> OpId {
        let keys = who.keys.clone();
        let certs = who.certs();
        self.emit(author, move |s, _| grant_body(s, &keys, &certs, role))
    }

    pub fn revoke(&mut self, author: &Dev, target: Id16) -> OpId {
        self.emit(author, move |s, _| revoke_body(s, target))
    }

    pub fn rotate(&mut self, author: &Dev) -> OpId {
        self.emit(author, |s, _| rotate_body(s))
    }
}

pub const SECRET: Id16 = [0x5E; 16];

fn dag_precedes(dag: &Dag, a: &OpId, b: &OpId) -> bool {
    use hirzla_access::authz::Causality;
    dag.precedes(a, b)
}

pub fn fake_op_id(locker: &Id16, opref: &OpRef, body: &[u8], deps: &[OpId]) -> OpId {
    let mut v = vec![Value::bytes(locker), opref.to_value(), Value::bytes(body)];
    v.extend(deps.iter().map(|d| Value::bytes(d)));
    sha384(&cbor::encode(&Value::Array(v)).unwrap())
}

/// A valid `Grant` body in the author's view.
pub fn grant_body(
    s: &LockerState,
    keys: &MemberKeys,
    certs: &[DeviceCert],
    role: Role,
) -> ControlBody {
    let existing = s.role(&keys.member);
    let (devices, envelopes) = match existing {
        Some(old) => {
            let env = if !old.is_reader() && role.is_reader() {
                let m = s.member(&keys.member).unwrap();
                envs(&m.devices.values().cloned().collect::<Vec<_>>())
            } else {
                Vec::new()
            };
            (Vec::new(), env)
        }
        None => (
            certs.to_vec(),
            if role.is_reader() {
                envs(certs)
            } else {
                Vec::new()
            },
        ),
    };
    ControlBody::Grant(Grant {
        member: keys.clone(),
        role,
        devices,
        envelopes,
        request_id: None,
        approvals: None,
        keylog_proof: None,
    })
}

pub fn prev_wraps(s: &LockerState) -> Vec<EpochWrap> {
    s.epoch_heads()
        .into_iter()
        .map(|e| EpochWrap {
            epoch: e,
            wrap: [0x77; 40],
        })
        .collect()
}

pub fn revoke_body(s: &LockerState, target: Id16) -> ControlBody {
    let readers: Vec<DeviceCert> = s
        .reader_devices()
        .into_iter()
        .filter(|((m, _), _)| *m != target)
        .map(|(_, c)| c.clone())
        .collect();
    ControlBody::Revoke(Revoke {
        member: target,
        envelopes: envs(&readers),
        prev: prev_wraps(s),
        request_id: None,
        approvals: None,
    })
}

pub fn rotate_body(s: &LockerState) -> ControlBody {
    let readers: Vec<DeviceCert> = s.reader_devices().into_values().cloned().collect();
    ControlBody::Rotate(Rotate {
        envelopes: envs(&readers),
        prev: prev_wraps(s),
    })
}

pub fn device_remove_body(s: &LockerState, rev: DeviceRevocation) -> ControlBody {
    let readers: Vec<DeviceCert> = s
        .reader_devices()
        .into_iter()
        .filter(|((m, d), _)| !(*m == rev.member && *d == rev.device))
        .map(|(_, c)| c.clone())
        .collect();
    ControlBody::DeviceRemove(DeviceRemove {
        revocation: rev,
        envelopes: envs(&readers),
        prev: prev_wraps(s),
    })
}

/// Approvals of `approvers` for an action published by `issuer`.
pub fn approvals(
    locker: Id16,
    request_id: Id16,
    action: SensitiveAction,
    target: Option<Id16>,
    detail: Option<u64>,
    issuer: Id16,
    approvers: &[&Dev],
) -> Vec<Approval> {
    approvers
        .iter()
        .map(|d| {
            ApprovalRequest {
                locker_id: locker,
                request_id,
                action,
                target,
                detail,
                issuer,
                approver_member: d.member,
                approver_device: d.device,
            }
            .approve(&d.sign)
            .unwrap()
        })
        .collect()
}

// ----- vector files -----

/// Parses `key = value` records separated by blank lines; `#` starts a comment.
pub fn records(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut out = Vec::new();
    let mut cur = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line.split_once('=').expect("key = value");
        cur.insert(k.trim().to_owned(), v.trim().to_owned());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
