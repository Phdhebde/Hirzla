//! Approval requests carried sealed by the server (ADR 0070, `sync-protocol.md` § 11.12):
//!
//! - `QuorumSend` seals the offer for each active device of each other `Owner`, and a cover
//!   for each device of the target, so that the server cannot tell the target;
//! - `ServerSync` hands the waiting mails over and takes the mails received: an offer goes
//!   to the inbox, an approval is collected as by `QuorumCollect`, a refusal is noted, a
//!   withdrawal removes the offer from the inbox;
//! - `QuorumRespond` signs or declines a received offer and sends the answer to the device
//!   of the initiator.
//!
//! A mail is acted on only once its signature holds under the sender's certificate active in
//! this device's own replica of the locker, and the sender is `Owner` there. A mail that does
//! not hold is dropped and acknowledged. Everything else stays possible by copy (§ 15.8).

use std::collections::BTreeMap;

use hirzla_access::Role;
use hirzla_sync::mail::{self, MailContent, MailKind};
use hirzla_sync::net::client::Client;
use hirzla_sync::net::proto::{code, MAX_MAIL_BATCH};
use hirzla_sync::text::{ApprovalOffer, ApprovalToken};
use hirzla_vault::cbor::{array_max, fixed, text_max, uint, Fields, Value};
use hirzla_vault::model::{DeviceCert, Id16};
use hirzla_vault::Vault;

use super::proto::{ReceivedRequest, ServerCode, ServerReply, MAX_INBOX, MAX_TEXT};
use super::{corrupt, general, internal, net, PendingRequest, ServerMode};
use crate::proto::ErrorCode;

/// Most sealed mails waiting to reach the server (`format.md` § 15.2, key 9).
pub(super) const MAX_OUTBOX: usize = 256;
/// Most rounds of `MailGet` in one synchronisation (the server holds at most 256 mails per
/// device, 64 per answer).
const MAX_ROUNDS: usize = 8;

/// A request received, to examine.
#[derive(Clone)]
pub(super) struct Received {
    /// The `hirzla-demande:…` text, as received.
    pub(super) offer: String,
    /// When this device received it.
    pub(super) received_ms: u64,
}

/// The courier state kept in the annex (version 5, key 9).
#[derive(Default, Clone)]
pub(super) struct Courier {
    /// Requests received, by locker and request.
    pub(super) inbox: BTreeMap<(Id16, Id16), Received>,
    /// Sealed mails waiting to reach the server, oldest first, with the request concerned.
    pub(super) outbox: Vec<(Id16, Vec<u8>)>,
}

impl Courier {
    pub(super) fn to_value(&self) -> Value {
        Value::map(vec![
            (
                1,
                Value::Array(
                    self.inbox
                        .values()
                        .map(|r| {
                            Value::map(vec![
                                (1, Value::text(&r.offer)),
                                (2, Value::Uint(r.received_ms)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                2,
                Value::Array(
                    self.outbox
                        .iter()
                        .map(|(r, m)| Value::map(vec![(1, Value::bytes(r)), (2, Value::bytes(m))]))
                        .collect(),
                ),
            ),
        ])
    }

    pub(super) fn from_value(v: &Value) -> Result<Courier, ServerCode> {
        let f = Fields::new(v, &[1, 2]).map_err(corrupt)?;
        let mut c = Courier::default();
        let mut last: Option<(Id16, Id16)> = None;
        for it in array_max(f.req(1).map_err(corrupt)?, MAX_INBOX).map_err(corrupt)? {
            let g = Fields::new(it, &[1, 2]).map_err(corrupt)?;
            let offer = text_max(g.req(1).map_err(corrupt)?, MAX_TEXT)
                .map_err(corrupt)?
                .to_owned();
            let o = ApprovalOffer::decode(&offer).map_err(corrupt)?;
            let key = (o.locker_id, o.request_id);
            if last.is_some_and(|l| l >= key) {
                return Err(general(ErrorCode::Corrupt));
            }
            last = Some(key);
            c.inbox.insert(
                key,
                Received {
                    offer,
                    received_ms: uint(g.req(2).map_err(corrupt)?).map_err(corrupt)?,
                },
            );
        }
        for it in array_max(f.req(2).map_err(corrupt)?, MAX_OUTBOX).map_err(corrupt)? {
            let g = Fields::new(it, &[1, 2]).map_err(corrupt)?;
            c.outbox.push((
                fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?,
                hirzla_vault::cbor::bytes_max(g.req(2).map_err(corrupt)?, mail::MAX_MAIL_LEN)
                    .map_err(corrupt)?
                    .to_vec(),
            ));
        }
        Ok(c)
    }
}

fn content(
    kind: MailKind,
    request: Option<(Id16, Id16)>,
    text: Option<String>,
    now: u64,
) -> MailContent {
    MailContent {
        kind,
        request,
        text,
        sent_ms: now,
    }
}

impl ServerMode {
    /// Seals `content` for the device `to` and puts it in the outbox.
    fn enqueue(
        &mut self,
        request: Id16,
        to: &DeviceCert,
        content: &MailContent,
    ) -> Result<(), ServerCode> {
        let (_, bytes) = mail::seal(&self.device, to, content).map_err(internal)?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if j.courier.outbox.len() >= MAX_OUTBOX {
            return Err(general(ErrorCode::InvalidInput));
        }
        j.courier.outbox.push((request, bytes));
        Ok(())
    }

    /// Mails of `request` still in the outbox.
    pub(super) fn queued(&self, request: &Id16) -> u64 {
        self.joined.as_ref().map_or(0, |j| {
            j.courier
                .outbox
                .iter()
                .filter(|(r, _)| r == request)
                .count() as u64
        })
    }

    /// `QuorumSend` (`docs/api-locale.md` § 15.10): the offer to each active device of each
    /// other `Owner` not yet served, a cover to each device of the target; then hands the
    /// outbox to the server if it is reachable. Idempotent for the devices already served.
    pub(super) fn quorum_send(
        &mut self,
        vault: &Vault,
        request: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let me = self.device.member_id();
        let mut p = self
            .joined()?
            .requests
            .get(&request)
            .cloned()
            .ok_or(general(ErrorCode::NotFound))?;
        let offer = self.offer_of(request, &p)?;
        let now = self.now();
        let mut to: Vec<(Id16, DeviceCert, MailKind)> = Vec::new();
        {
            let j = self.joined()?;
            let s = j
                .lockers
                .get(&p.locker)
                .ok_or(general(ErrorCode::NotFound))?;
            if !s.access {
                return Err(ServerCode::Forbidden);
            }
            let state = s
                .replica
                .authorization()
                .ok_or(ServerCode::Forbidden)?
                .access()
                .state();
            for m in state.owners_by_seniority() {
                if m == me {
                    continue;
                }
                let kind = if Some(m) == p.target {
                    MailKind::Cover
                } else {
                    MailKind::Offer
                };
                for (d, cert) in state.member(&m).map(|e| &e.devices).into_iter().flatten() {
                    if !p.recipients.contains(&(m, *d)) {
                        to.push((m, cert.clone(), kind));
                    }
                }
            }
            let room = MAX_OUTBOX.saturating_sub(j.courier.outbox.len());
            if to.len() > room {
                return Err(general(ErrorCode::InvalidInput));
            }
        }
        for (m, cert, kind) in to {
            let c = match kind {
                MailKind::Offer => {
                    content(kind, Some((p.locker, request)), Some(offer.clone()), now)
                }
                _ => content(MailKind::Cover, None, None, now),
            };
            self.enqueue(request, &cert, &c)?;
            p.recipients.push((m, cert.device));
        }
        p.recipients.sort_unstable();
        p.sent_ms = Some(now);
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .requests
            .insert(request, p.clone());
        self.save(vault)?;
        // Best effort: what does not reach the server now leaves at the next `ServerSync`.
        if let Ok(mut client) = self.session() {
            let _ = self.flush_outbox(&mut client);
            let _ = client.bye();
            self.save(vault)?;
        }
        Ok(ServerReply::Request(self.quorum_state(request, &p)?))
    }

    /// Puts the withdrawal of a request sent through the server in the outbox (applied or
    /// cancelled): to the devices served, a cover to the target's.
    pub(super) fn enqueue_withdrawn(&mut self, request: Id16, p: &PendingRequest) {
        if p.sent_ms.is_none() {
            return;
        }
        let now = self.now();
        let certs: Vec<(Id16, DeviceCert)> = {
            let Ok(j) = self.joined() else {
                return;
            };
            let Some(state) = j
                .lockers
                .get(&p.locker)
                .and_then(|s| s.replica.authorization())
                .map(|a| a.access().state())
            else {
                return;
            };
            p.recipients
                .iter()
                .filter_map(|(m, d)| state.active_device(m, d).map(|c| (*m, c.clone())))
                .collect()
        };
        for (m, cert) in certs {
            let c = if Some(m) == p.target {
                content(MailKind::Cover, None, None, now)
            } else {
                content(MailKind::Withdrawn, Some((p.locker, request)), None, now)
            };
            // Best effort: a full outbox leaves the offer in the inbox of the others, where
            // applying it is refused anyway.
            let _ = self.enqueue(request, &cert, &c);
        }
    }

    /// Hands the outbox to the server, 64 mails at a time. A mail the server refused for
    /// good (not a full mailbox) is dropped.
    pub(super) fn flush_outbox(&mut self, client: &mut Client) -> Result<(), ServerCode> {
        let all = std::mem::take(
            &mut self
                .joined
                .as_mut()
                .ok_or(ServerCode::NotJoined)?
                .courier
                .outbox,
        );
        let mut kept = Vec::new();
        let mut failure = None;
        for chunk in all.chunks(MAX_MAIL_BATCH) {
            if failure.is_some() {
                kept.extend_from_slice(chunk);
                continue;
            }
            let bytes: Vec<Vec<u8>> = chunk.iter().map(|(_, m)| m.clone()).collect();
            match client.mail_put(&bytes) {
                Ok(statuses) => {
                    for (item, status) in chunk.iter().zip(statuses) {
                        if status == code::QUOTA {
                            kept.push(item.clone());
                        }
                    }
                }
                Err(e) => {
                    failure = Some(net(e));
                    kept.extend_from_slice(chunk);
                }
            }
        }
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .courier
            .outbox = kept;
        failure.map_or(Ok(()), Err)
    }

    /// Takes the mails waiting on the server, acts on them, and acknowledges them once the
    /// annex holds the result.
    pub(super) fn fetch_mail(
        &mut self,
        vault: &Vault,
        client: &mut Client,
    ) -> Result<(), ServerCode> {
        let mut ack: Vec<Id16> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            let got = client.mail_get(&ack, MAX_MAIL_BATCH as u64).map_err(net)?;
            if got.items.is_empty() {
                return Ok(());
            }
            let now = self.now();
            ack = Vec::with_capacity(got.items.len());
            for item in got.items {
                self.take_mail(&item.mail, now);
                ack.push(item.mail_id);
            }
            self.save(vault)?;
        }
        // The last mails acted on are acknowledged at the next synchronisation.
        Ok(())
    }

    /// Acts on one mail; drops it silently if it does not hold (ADR 0070, point 2).
    fn take_mail(&mut self, bytes: &[u8], now: u64) {
        let Ok(opened) = mail::open(&self.device, bytes) else {
            return;
        };
        let c = &opened.content;
        let Some((locker, request)) = c.request else {
            // A cover: nothing to show.
            return;
        };
        let from = opened.header.from_member;
        let from_device = opened.header.from_device;
        let sender_ok = self
            .joined
            .as_ref()
            .and_then(|j| j.lockers.get(&locker))
            .and_then(|s| s.replica.authorization())
            .map(|a| a.access().state())
            .is_some_and(|state| {
                state.role(&from) == Some(Role::Owner)
                    && state
                        .active_device(&from, &from_device)
                        .is_some_and(|cert| opened.verify(cert).is_ok())
            });
        if !sender_ok {
            return;
        }
        match c.kind {
            MailKind::Cover => {}
            MailKind::Offer => {
                let Some(offer) = c
                    .text
                    .as_deref()
                    .and_then(|t| ApprovalOffer::decode(t).ok())
                else {
                    return;
                };
                let fits = offer.locker_id == locker
                    && offer.request_id == request
                    && offer.issuer == from
                    && offer.issuer_device == from_device
                    && self.may_sign(&offer).is_ok();
                let Some(j) = self.joined.as_mut() else {
                    return;
                };
                if fits
                    && !j.courier.inbox.contains_key(&(locker, request))
                    && j.courier.inbox.len() < MAX_INBOX
                {
                    if let Some(text) = &c.text {
                        j.courier.inbox.insert(
                            (locker, request),
                            Received {
                                offer: text.clone(),
                                received_ms: now,
                            },
                        );
                    }
                }
            }
            MailKind::Token => {
                let Some(token) = c
                    .text
                    .as_deref()
                    .and_then(|t| ApprovalToken::decode(t).ok())
                else {
                    return;
                };
                if token.locker_id == locker
                    && token.request_id == request
                    && token.approval.member == from
                    && token.approval.device == from_device
                {
                    // Already counted, or no longer pending: nothing to do.
                    let _ = self.add_approval(&token);
                }
            }
            MailKind::Decline => {
                let Some(j) = self.joined.as_mut() else {
                    return;
                };
                if let Some(p) = j.requests.get_mut(&request) {
                    let asked = p.recipients.iter().any(|(m, _)| *m == from);
                    let approved = p.approvals.iter().any(|a| a.member == from);
                    if p.locker == locker
                        && asked
                        && Some(from) != p.target
                        && !approved
                        && !p.declined.contains(&from)
                    {
                        p.declined.push(from);
                        p.declined.sort_unstable();
                    }
                }
            }
            MailKind::Withdrawn => {
                let Some(j) = self.joined.as_mut() else {
                    return;
                };
                let from_issuer = j
                    .courier
                    .inbox
                    .get(&(locker, request))
                    .and_then(|r| ApprovalOffer::decode(&r.offer).ok())
                    .is_some_and(|o| o.issuer == from && o.issuer_device == from_device);
                if from_issuer {
                    j.courier.inbox.remove(&(locker, request));
                }
            }
        }
    }

    /// `QuorumInbox`: the requests received, oldest first, as `QuorumInspect` reads them.
    pub(super) fn quorum_inbox(&self) -> Result<ServerReply, ServerCode> {
        let j = self.joined()?;
        let mut out = Vec::new();
        for ((locker, request), r) in &j.courier.inbox {
            let ServerReply::Inspected {
                name,
                action,
                target,
                target_fingerprint,
                detail,
                issuer,
                issuer_fingerprint,
                can_sign,
                target_name,
                issuer_name,
                ..
            } = self.quorum_inspect(&r.offer)?
            else {
                continue;
            };
            let state = j
                .lockers
                .get(locker)
                .and_then(|s| s.replica.authorization())
                .map(|a| a.access().state());
            let verified = |m: &Id16| {
                state
                    .and_then(|st| st.member(m))
                    .is_some_and(|e| self.fingerprint_verified(&e.keys))
            };
            out.push(ReceivedRequest {
                request: *request,
                locker: *locker,
                name,
                action,
                target,
                target_fingerprint,
                target_name,
                target_verified: target.as_ref().is_some_and(verified),
                detail,
                issuer,
                issuer_fingerprint,
                issuer_name,
                issuer_verified: verified(&issuer),
                can_sign,
                required: state.map_or(2, |st| u64::from(st.quorum())),
                received_ms: r.received_ms,
                offer: r.offer.clone(),
            });
        }
        out.sort_by_key(|r| (r.received_ms, r.locker, r.request));
        Ok(ServerReply::Inbox(out))
    }

    /// `QuorumRespond`: signs (as `QuorumApprove`) or declines a received request, sends the
    /// answer to the initiator's device and takes the request out of the inbox.
    pub(super) fn quorum_respond(
        &mut self,
        vault: &Vault,
        locker: Id16,
        request: Id16,
        accept: bool,
    ) -> Result<ServerReply, ServerCode> {
        let text = self
            .joined()?
            .courier
            .inbox
            .get(&(locker, request))
            .map(|r| r.offer.clone())
            .ok_or(general(ErrorCode::NotFound))?;
        let offer = ApprovalOffer::decode(&text).map_err(|_| ServerCode::ApprovalInvalid)?;
        let issuer_cert = self
            .joined()?
            .lockers
            .get(&locker)
            .and_then(|s| s.replica.authorization())
            .and_then(|a| {
                a.access()
                    .state()
                    .active_device(&offer.issuer, &offer.issuer_device)
                    .cloned()
            });
        let Some(issuer_cert) = issuer_cert else {
            // The initiator's device is gone: nobody can collect an answer any more.
            self.joined
                .as_mut()
                .ok_or(ServerCode::NotJoined)?
                .courier
                .inbox
                .remove(&(locker, request));
            self.save(vault)?;
            return Err(general(ErrorCode::NotFound));
        };
        let now = self.now();
        let (reply, c) = if accept {
            let ServerReply::Approved(token) = self.quorum_approve(&text)? else {
                return Err(general(ErrorCode::Internal));
            };
            let c = content(
                MailKind::Token,
                Some((locker, request)),
                Some(token.clone()),
                now,
            );
            (ServerReply::Approved(token), c)
        } else {
            let c = content(MailKind::Decline, Some((locker, request)), None, now);
            (ServerReply::Done, c)
        };
        self.enqueue(request, &issuer_cert, &c)?;
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .courier
            .inbox
            .remove(&(locker, request));
        self.save(vault)?;
        if let Ok(mut client) = self.session() {
            let _ = self.flush_outbox(&mut client);
            let _ = client.bye();
            self.save(vault)?;
        }
        Ok(reply)
    }
}
