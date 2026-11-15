//! Unit tests of the machine member: enrolment, control code, strict decoding of the agent
//! requests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::proto::{is_agent_request, AgentCode, AgentRequest, AGENT_VERSION};
use super::*;
use crate::proto::ErrorCode;

#[test]
fn enrolment_round_trip_and_checks() {
    let (device, e) = enrol(5).unwrap();
    assert_eq!(device.member_id(), e.member.member);
    assert_eq!(device.device_id(), e.cert.device);
    assert_eq!(e.control_code.len(), 20);
    assert!(e
        .control_code
        .bytes()
        .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)));
    let back = Enrolment::decode(&e.encode().unwrap()).unwrap();
    assert_eq!(back, e);
    // A certificate not signed by the member key is refused.
    let (_, other) = enrol(5).unwrap();
    let forged = Enrolment {
        member: other.member.clone(),
        ..e.clone()
    };
    assert_eq!(
        Enrolment::decode(&forged.encode().unwrap()),
        Err(AgentError::InvalidInput)
    );
    assert_eq!(Enrolment::decode(&[0xa0]), Err(AgentError::InvalidInput));
}

#[test]
fn control_code_is_base32_of_the_hash() {
    // Recomputed independently: 13 bytes of the hash give 104 bits, 20 characters use 100.
    let (_, e) = enrol(1).unwrap();
    let v = Value::map(vec![
        (1, Value::bytes(&e.cert.sig)),
        (2, Value::bytes(&e.cert.kem)),
    ]);
    let d = sha384(&cbor::encode(&v).unwrap());
    let mut bits = String::new();
    for b in &d[..13] {
        bits.push_str(&format!("{b:08b}"));
    }
    let expected: String = (0..20)
        .map(|i| {
            let n = u8::from_str_radix(&bits[i * 5..i * 5 + 5], 2).unwrap();
            char::from(BASE32[n as usize])
        })
        .collect();
    assert_eq!(e.control_code, expected);
}

#[test]
fn agent_requests_round_trip() {
    let reqs = vec![
        AgentRequest::AgentStatus,
        AgentRequest::AgentEnrol,
        AgentRequest::AgentJoin {
            locker: [1; 16],
            genesis: Some([2; 48]),
        },
        AgentRequest::AgentIngest {
            locker: [1; 16],
            ops: vec![vec![1, 2, 3]],
        },
        AgentRequest::AgentOutbox { locker: [1; 16] },
        AgentRequest::AgentAck {
            locker: [1; 16],
            ops: vec![[3; 48]],
        },
        AgentRequest::SessionOpen { grant: vec![9; 10] },
        AgentRequest::Rotate { grant: vec![9; 10] },
    ];
    for r in reqs {
        let f = r.encode(3).unwrap();
        assert!(is_agent_request(&f));
        assert_eq!(AgentRequest::decode(&f).unwrap(), (3, r));
    }
}

#[test]
fn agent_requests_are_decoded_strictly() {
    let enc = |v: Value| cbor::encode(&v).unwrap().to_vec();
    let req = |ver: u64, op: u64, args: Option<Value>| {
        let mut e = vec![
            (1, Value::Uint(ver)),
            (2, Value::Uint(5)),
            (3, Value::Uint(op)),
        ];
        if let Some(a) = args {
            e.push((4, a));
        }
        enc(Value::map(e))
    };
    let malformed = AgentCode::General(ErrorCode::Malformed);
    // Wrong version.
    assert_eq!(
        AgentRequest::decode(&req(1, 20, None)),
        Err((5, AgentCode::General(ErrorCode::UnsupportedVersion)))
    );
    // Unknown operation in the agent range.
    assert_eq!(
        AgentRequest::decode(&req(AGENT_VERSION, 29, None)),
        Err((5, AgentCode::General(ErrorCode::UnknownOperation)))
    );
    // Arguments where none are taken, missing where required, unknown key, bad lengths.
    let cases = [
        req(AGENT_VERSION, 20, Some(Value::map(vec![]))),
        req(AGENT_VERSION, 22, None),
        req(
            AGENT_VERSION,
            22,
            Some(Value::map(vec![(1, Value::bytes(&[0; 15]))])),
        ),
        req(
            AGENT_VERSION,
            22,
            Some(Value::map(vec![
                (1, Value::bytes(&[0; 16])),
                (3, Value::Uint(1)),
            ])),
        ),
        req(
            AGENT_VERSION,
            25,
            Some(Value::map(vec![
                (1, Value::bytes(&[0; 16])),
                (2, Value::Array(vec![Value::bytes(&[0; 47])])),
            ])),
        ),
        req(
            AGENT_VERSION,
            26,
            Some(Value::map(vec![(1, Value::text("grant"))])),
        ),
        req(
            AGENT_VERSION,
            26,
            Some(Value::map(vec![(
                1,
                Value::bytes(&vec![0; hirzla_access::hornn::MAX_SIGNED_LEN + 1]),
            )])),
        ),
    ];
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(AgentRequest::decode(c), Err((5, malformed)), "case {i}");
    }
    // General operations are not agent requests.
    assert!(!is_agent_request(&req(1, 6, None)));
    assert!(!is_agent_request(&[0xff]));
}
