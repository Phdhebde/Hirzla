//! What the core does with an agent request (`docs/api-locale.md` § 14).

use std::sync::Arc;

use hirzla_access::hornn::HornnTrust;

use super::proto::{AgentCode, AgentReply, AgentRequest};
use super::rotation::RotationTransport;
use super::{enrol, AgentError, MachineMember};
use crate::events::{Event, Log};
use crate::proto::ErrorCode;

/// Configuration of the agent profile of a core.
pub struct AgentConfig {
    /// Hornn's pinned issuer and key.
    pub trust: HornnTrust,
    /// Start of the core, milliseconds since the Unix epoch.
    pub started_ms: u64,
    /// Password change transport; `None` until a real one exists (ADR 0030): `Rotate`
    /// answers `Unsupported`.
    pub transport: Option<Box<dyn RotationTransport>>,
}

/// The agent profile of a core: absent identity until `AgentEnrol`, then a machine member.
pub struct AgentService {
    trust: HornnTrust,
    started_ms: u64,
    transport: Option<Box<dyn RotationTransport>>,
    member: Option<MachineMember>,
    clock: Option<fn() -> u64>,
    log: Arc<Log>,
}

fn code(e: AgentError) -> AgentCode {
    match e {
        AgentError::Grant(r) => AgentCode::GrantRefused(r.code()),
        AgentError::UnknownLocker => AgentCode::UnknownLocker,
        AgentError::NotFound => AgentCode::General(ErrorCode::NotFound),
        AgentError::InvalidInput => AgentCode::General(ErrorCode::InvalidInput),
        AgentError::Transport => AgentCode::TransportRefused,
        AgentError::PublishPending => AgentCode::PublishPending,
        AgentError::Sync | AgentError::Internal => AgentCode::General(ErrorCode::Internal),
    }
}

impl AgentService {
    /// A service without identity.
    #[must_use]
    pub fn new(config: AgentConfig, log: Arc<Log>) -> AgentService {
        AgentService {
            trust: config.trust,
            started_ms: config.started_ms,
            transport: config.transport,
            member: None,
            clock: None,
            log,
        }
    }

    /// Replaces the wall clock (tests).
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = Some(clock);
        if let Some(m) = &mut self.member {
            m.set_clock(clock);
        }
    }

    /// The machine member, once enrolled (tests).
    #[must_use]
    pub fn member(&self) -> Option<&MachineMember> {
        self.member.as_ref()
    }

    fn now(&self) -> u64 {
        self.clock.map_or_else(
            || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            },
            |c| c(),
        )
    }

    /// Handles one request and logs its outcome (operation and fixed words only).
    pub fn handle(&mut self, request: AgentRequest) -> Result<AgentReply, AgentCode> {
        let op = request.op();
        let result = self.dispatch(request);
        self.log.record(Event::AgentRequest {
            op,
            result: match &result {
                Ok(_) => "ok",
                Err(AgentCode::GrantRefused(n)) => refusal_name(*n),
                Err(c) => c.name(),
            },
        });
        result
    }

    fn member_mut(&mut self) -> Result<&mut MachineMember, AgentCode> {
        self.member.as_mut().ok_or(AgentCode::NotEnrolled)
    }

    fn dispatch(&mut self, request: AgentRequest) -> Result<AgentReply, AgentCode> {
        match request {
            AgentRequest::AgentStatus => Ok(AgentReply::Status {
                identity: self
                    .member
                    .as_ref()
                    .map(|m| (m.device().member_id(), m.device().device_id())),
                lockers: self
                    .member
                    .as_ref()
                    .map(MachineMember::lockers)
                    .unwrap_or_default(),
                issuer: self.trust.issuer(),
                started_ms: self.started_ms,
            }),
            AgentRequest::AgentEnrol => {
                if self.member.is_some() {
                    return Err(AgentCode::AlreadyEnrolled);
                }
                let (device, e) = enrol(self.now()).map_err(code)?;
                let mut m = MachineMember::new(device, self.trust.clone(), self.started_ms);
                if let Some(c) = self.clock {
                    m.set_clock(c);
                }
                self.member = Some(m);
                Ok(AgentReply::Enrolled {
                    enrolment: e.encode().map_err(code)?,
                    control_code: e.control_code,
                })
            }
            AgentRequest::AgentJoin { locker, genesis } => {
                self.member_mut()?.join(locker, genesis).map_err(code)?;
                Ok(AgentReply::Done)
            }
            AgentRequest::AgentIngest { locker, ops } => {
                let r = self.member_mut()?.ingest(&locker, ops).map_err(code)?;
                Ok(AgentReply::Ingested {
                    added: r.added as u64,
                    duplicates: r.duplicates as u64,
                })
            }
            AgentRequest::AgentOutbox { locker } => Ok(AgentReply::Outbox(
                self.member_mut()?.outbox(&locker).map_err(code)?,
            )),
            AgentRequest::AgentAck { locker, ops } => {
                self.member_mut()?.ack(&locker, &ops).map_err(code)?;
                Ok(AgentReply::Done)
            }
            AgentRequest::SessionOpen { grant } => {
                let c = self.member_mut()?.open_session(&grant).map_err(code)?;
                Ok(AgentReply::Session {
                    fields: c.fields,
                    urls: c.urls,
                    hosts: c.hosts,
                })
            }
            AgentRequest::Rotate { grant } => {
                let member = self.member.as_mut().ok_or(AgentCode::NotEnrolled)?;
                let transport = self
                    .transport
                    .as_mut()
                    .ok_or(AgentCode::General(ErrorCode::Unsupported))?;
                let o = member.rotate(&grant, transport.as_mut()).map_err(code)?;
                Ok(AgentReply::Rotated {
                    op: o.op,
                    confirmed: o.confirmed,
                })
            }
        }
    }
}

fn refusal_name(code: u64) -> &'static str {
    use hirzla_access::hornn::GrantRefusal as G;
    [
        G::Malformed,
        G::BadSignature,
        G::WrongIssuer,
        G::WrongAgent,
        G::NotYetValid,
        G::Expired,
        G::Lifetime,
        G::BeforeStart,
        G::Replayed,
        G::GuardFull,
        G::Requester,
        G::AgentRole,
        G::Unknown,
    ]
    .into_iter()
    .find(|g| g.code() == code)
    .map_or("grant_refused", G::name)
}
