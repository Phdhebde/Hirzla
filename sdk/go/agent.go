package hirzla

// Field codes of docs/format.md § 8 that a session may return.
const (
	FieldUsername      = 10
	FieldPassword      = 11
	FieldSSHPassphrase = 22
)

// Status is the state of the machine member (operation 20).
type Status struct {
	// Enrolled tells whether the machine has its identity.
	Enrolled bool
	// Member and Device identify the machine once enrolled (16 bytes each).
	Member, Device []byte
	// Lockers served (16 bytes each).
	Lockers [][]byte
	// Issuer is the pinned Hornn instance (16 bytes).
	Issuer []byte
	// StartedMs is the start of the core: grants issued before are refused.
	StartedMs uint64
}

// Enrolment is what an owner needs to admit the machine (operation 21). Public data.
type Enrolment struct {
	// Encoded is the canonical {1: MemberKeys, 2: DeviceCert}, opaque to the SDK.
	Encoded []byte
	// ControlCode is compared out of band before the owner grants a role.
	ControlCode string
}

// OutboxItem is an operation the core asks to send to the relay.
type OutboxItem struct {
	// ID is the SHA-384 of the operation (48 bytes), to acknowledge it.
	ID []byte
	// Op is the encoded operation, opaque to the SDK.
	Op []byte
}

// Credentials are the values unsealed for one session. Secret: call Wipe as soon as the
// connection to the target is open. The values are byte slices, never strings, so that they
// can be erased; the Go runtime may still have copied them (see README, limits).
type Credentials struct {
	// Fields by code (FieldUsername, FieldPassword, FieldSSHPassphrase).
	Fields map[uint64][]byte
	// URLs and Hosts of the secret (not secret): check that the target Hornn gave is among
	// them before connecting.
	URLs, Hosts []string
}

// Wipe zeroes every value.
func (c *Credentials) Wipe() {
	if c == nil {
		return
	}
	for k, v := range c.Fields {
		clear(v)
		delete(c.Fields, k)
	}
}

// RotationResult tells what a rotation did (operation 27).
type RotationResult struct {
	// Op is the SHA-384 of the published SecretPut (48 bytes).
	Op []byte
	// Confirmed is false when the target's answer was lost: the new version is published
	// anyway and the previous one stays in the history.
	Confirmed bool
}

func copyBytes(b []byte) []byte { return append([]byte(nil), b...) }

func noBody(body *value) error {
	if body != nil {
		body.wipe()
		return ErrMalformed
	}
	return nil
}

// AgentStatus returns the state of the machine member.
func (c *Client) AgentStatus() (*Status, error) {
	body, err := c.call(opAgentStatus, nil)
	if err != nil {
		return nil, err
	}
	f, err := asFields(body, 1, 2, 3, 4, 5, 6)
	if err != nil {
		return nil, err
	}
	s := &Status{}
	if s.Enrolled, err = f.bool(1); err != nil {
		return nil, err
	}
	if s.Enrolled {
		m, err1 := f.fixed(2, 16)
		d, err2 := f.fixed(3, 16)
		if err1 != nil || err2 != nil {
			return nil, ErrMalformed
		}
		s.Member, s.Device = copyBytes(m), copyBytes(d)
	} else if f.opt(2) != nil || f.opt(3) != nil {
		return nil, ErrMalformed
	}
	lockers, err := f.array(4, 256)
	if err != nil {
		return nil, err
	}
	for _, l := range lockers {
		if l.k != kBytes || len(l.b) != 16 {
			return nil, ErrMalformed
		}
		s.Lockers = append(s.Lockers, copyBytes(l.b))
	}
	issuer, err := f.fixed(5, 16)
	if err != nil {
		return nil, err
	}
	s.Issuer = copyBytes(issuer)
	if s.StartedMs, err = f.uint(6); err != nil {
		return nil, err
	}
	return s, nil
}

// Enrol has the core generate the machine identity: its own hybrid key pairs, which never
// leave the core.
func (c *Client) Enrol() (*Enrolment, error) {
	body, err := c.call(opAgentEnrol, nil)
	if err != nil {
		return nil, err
	}
	f, err := asFields(body, 1, 2)
	if err != nil {
		return nil, err
	}
	enc, err1 := f.bytes(1, 16*1024)
	code, err2 := f.text(2, 64)
	if err1 != nil || err2 != nil {
		return nil, ErrMalformed
	}
	return &Enrolment{Encoded: copyBytes(enc), ControlCode: string(code)}, nil
}

func lockerArg(locker []byte, extra ...value) (*value, error) {
	if len(locker) != 16 {
		return nil, &Error{Code: CodeInvalidInput}
	}
	keys := []uint64{1}
	vals := []value{vBytes(locker)}
	for i, e := range extra {
		keys = append(keys, uint64(i+2))
		vals = append(vals, e)
	}
	v := vMap(keys, vals)
	return &v, nil
}

// Join starts serving a locker the machine was admitted to. genesis (48 bytes) is the
// creation of the locker when known, or nil.
func (c *Client) Join(locker, genesis []byte) error {
	var extra []value
	if genesis != nil {
		if len(genesis) != 48 {
			return &Error{Code: CodeInvalidInput}
		}
		extra = append(extra, vBytes(genesis))
	}
	args, err := lockerArg(locker, extra...)
	if err != nil {
		return err
	}
	body, err := c.call(opAgentJoin, args)
	if err != nil {
		return err
	}
	return noBody(body)
}

// Ingest hands operations of a locker, received from the relay, to the core. Returns how
// many were new and how many already known.
func (c *Client) Ingest(locker []byte, ops [][]byte) (added, duplicates uint64, err error) {
	if len(ops) > MaxOps {
		return 0, 0, &Error{Code: CodeInvalidInput}
	}
	items := make([]value, 0, len(ops))
	for _, o := range ops {
		if len(o) > MaxOpLen {
			return 0, 0, &Error{Code: CodeInvalidInput}
		}
		items = append(items, vBytes(o))
	}
	args, err := lockerArg(locker, vArray(items))
	if err != nil {
		return 0, 0, err
	}
	body, err := c.call(opAgentIngest, args)
	if err != nil {
		return 0, 0, err
	}
	f, err := asFields(body, 1, 2)
	if err != nil {
		return 0, 0, err
	}
	added, err1 := f.uint(1)
	duplicates, err2 := f.uint(2)
	if err1 != nil || err2 != nil {
		return 0, 0, ErrMalformed
	}
	return added, duplicates, nil
}

// Outbox returns the operations of a locker the core wants sent to the relay.
func (c *Client) Outbox(locker []byte) ([]OutboxItem, error) {
	args, err := lockerArg(locker)
	if err != nil {
		return nil, err
	}
	body, err := c.call(opAgentOutbox, args)
	if err != nil {
		return nil, err
	}
	f, err := asFields(body, 1)
	if err != nil {
		return nil, err
	}
	items, err := f.array(1, MaxOps)
	if err != nil {
		return nil, err
	}
	out := make([]OutboxItem, 0, len(items))
	for i := range items {
		it, err := asFields(&items[i], 1, 2)
		if err != nil {
			return nil, err
		}
		id, err1 := it.fixed(1, 48)
		op, err2 := it.bytes(2, MaxOpLen)
		if err1 != nil || err2 != nil {
			return nil, ErrMalformed
		}
		out = append(out, OutboxItem{ID: copyBytes(id), Op: copyBytes(op)})
	}
	return out, nil
}

// Ack tells the core that the relay accepted these operations (48-byte identifiers).
func (c *Client) Ack(locker []byte, ids [][]byte) error {
	if len(ids) > MaxOps {
		return &Error{Code: CodeInvalidInput}
	}
	items := make([]value, 0, len(ids))
	for _, id := range ids {
		if len(id) != 48 {
			return &Error{Code: CodeInvalidInput}
		}
		items = append(items, vBytes(id))
	}
	args, err := lockerArg(locker, vArray(items))
	if err != nil {
		return err
	}
	body, err := c.call(opAgentAck, args)
	if err != nil {
		return err
	}
	return noBody(body)
}

func grantArg(grant []byte) (*value, error) {
	if len(grant) == 0 || len(grant) > MaxGrant {
		return nil, &Error{Code: CodeInvalidInput}
	}
	v := vMap([]uint64{1}, []value{vBytes(grant)})
	return &v, nil
}

func texts(vs []value, max int) ([]string, error) {
	if len(vs) > max {
		return nil, ErrMalformed
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.k != kText {
			return nil, ErrMalformed
		}
		out = append(out, string(v.b))
	}
	return out, nil
}

// OpenSession presents a session grant signed by Hornn. The core checks it (hybrid
// signature, issuer, recipient, expiry, single use, roles) and returns the fields it names.
// The grant is opaque to the SDK. Wipe the result after use.
func (c *Client) OpenSession(grant []byte) (*Credentials, error) {
	args, err := grantArg(grant)
	if err != nil {
		return nil, err
	}
	body, err := c.call(opSessionOpen, args)
	if err != nil {
		return nil, err
	}
	defer body.wipe()
	f, err := asFields(body, 1, 2, 3)
	if err != nil {
		return nil, err
	}
	fm := f.opt(1)
	if fm == nil || fm.k != kMap || len(fm.keys) == 0 || len(fm.keys) > 3 {
		return nil, ErrMalformed
	}
	cred := &Credentials{Fields: make(map[uint64][]byte, len(fm.keys))}
	for i, k := range fm.keys {
		v := fm.items[i]
		if v.k != kText || (k != FieldUsername && k != FieldPassword && k != FieldSSHPassphrase) {
			cred.Wipe()
			return nil, ErrMalformed
		}
		cred.Fields[k] = copyBytes(v.b)
	}
	urls, err1 := f.array(2, 64)
	hosts, err2 := f.array(3, 64)
	if err1 != nil || err2 != nil {
		cred.Wipe()
		return nil, ErrMalformed
	}
	if cred.URLs, err = texts(urls, 64); err != nil {
		cred.Wipe()
		return nil, err
	}
	if cred.Hosts, err = texts(hosts, 64); err != nil {
		cred.Wipe()
		return nil, err
	}
	return cred, nil
}

// Rotate presents a rotation grant signed by Hornn at the end of a session. The core
// changes the password on the target named by the secret and publishes the new version.
func (c *Client) Rotate(grant []byte) (*RotationResult, error) {
	args, err := grantArg(grant)
	if err != nil {
		return nil, err
	}
	body, err := c.call(opRotate, args)
	if err != nil {
		return nil, err
	}
	f, err := asFields(body, 1, 2)
	if err != nil {
		return nil, err
	}
	op, err1 := f.fixed(1, 48)
	ok, err2 := f.bool(2)
	if err1 != nil || err2 != nil {
		return nil, ErrMalformed
	}
	return &RotationResult{Op: copyBytes(op), Confirmed: ok}, nil
}
