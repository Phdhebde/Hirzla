package hirzla

import "fmt"

// Code is the status of a refused request (docs/api-locale.md § 7 and § 13.3).
type Code uint64

// General codes reused by the agent profile, and the codes of the agent profile.
const (
	CodeMalformed          Code = 1
	CodeUnsupportedVersion Code = 2
	CodeUnknownOperation   Code = 3
	CodeUnauthorized       Code = 4
	CodeNotFound           Code = 11
	CodeInvalidInput       Code = 13
	CodeUnsupported        Code = 14
	CodeBusy               Code = 15
	CodeInternal           Code = 17
	CodeNotEnrolled        Code = 30
	CodeAlreadyEnrolled    Code = 31
	CodeGrantRefused       Code = 32
	CodeTransportRefused   Code = 33
	CodePublishPending     Code = 34
	CodeUnknownLocker      Code = 35
)

// GrantReason tells why the core refused a session grant (docs/api-locale.md § 13.3).
type GrantReason uint64

// Reasons a grant is refused.
const (
	ReasonMalformed    GrantReason = 1
	ReasonBadSignature GrantReason = 2
	ReasonWrongIssuer  GrantReason = 3
	ReasonWrongAgent   GrantReason = 4
	ReasonNotYetValid  GrantReason = 5
	ReasonExpired      GrantReason = 6
	ReasonLifetime     GrantReason = 7
	ReasonBeforeStart  GrantReason = 8
	ReasonReplayed     GrantReason = 9
	ReasonGuardFull    GrantReason = 10
	ReasonRequester    GrantReason = 11
	ReasonAgentRole    GrantReason = 12
	ReasonUnknown      GrantReason = 13
)

var reasonNames = map[GrantReason]string{
	ReasonMalformed:    "malformed",
	ReasonBadSignature: "bad_signature",
	ReasonWrongIssuer:  "wrong_issuer",
	ReasonWrongAgent:   "wrong_agent",
	ReasonNotYetValid:  "not_yet_valid",
	ReasonExpired:      "expired",
	ReasonLifetime:     "lifetime",
	ReasonBeforeStart:  "before_start",
	ReasonReplayed:     "replayed",
	ReasonGuardFull:    "guard_full",
	ReasonRequester:    "requester",
	ReasonAgentRole:    "agent_role",
	ReasonUnknown:      "unknown",
}

func (r GrantReason) String() string {
	if n, ok := reasonNames[r]; ok {
		return n
	}
	return fmt.Sprintf("reason_%d", uint64(r))
}

// Error is a refusal from the core. It never carries a secret.
type Error struct {
	Code Code
	// Reason is set when Code is CodeGrantRefused.
	Reason GrantReason
}

func (e *Error) Error() string {
	if e.Code == CodeGrantRefused {
		return fmt.Sprintf("hirzla: grant refused (%s)", e.Reason)
	}
	return fmt.Sprintf("hirzla: refused (code %d)", uint64(e.Code))
}
