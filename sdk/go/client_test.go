//go:build unix

package hirzla

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeCore stands in for hirzla-core: it decodes each request with the strict decoder and
// answers with handler. It checks the envelope the way the core does.
type fakeCore struct {
	t       *testing.T
	ln      net.Listener
	path    string
	handler func(op uint64, args *value) (status uint64, body *value)
	mu      sync.Mutex
	seen    [][]byte
}

func (f *fakeCore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func privateDir(t *testing.T) string {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func newFakeCore(t *testing.T, h func(op uint64, args *value) (uint64, *value)) *fakeCore {
	path := filepath.Join(privateDir(t), "core.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCore{t: t, ln: ln, path: path, handler: h}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeCore) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			for {
				frame, err := readFrame(conn)
				if err != nil {
					return
				}
				f.mu.Lock()
				f.seen = append(f.seen, append([]byte(nil), frame...))
				f.mu.Unlock()
				req, err := decode(frame)
				if err != nil {
					return
				}
				fl, err := asFields(&req, 1, 2, 3, 4)
				if err != nil {
					return
				}
				v, _ := fl.uint(1)
				id, _ := fl.uint(2)
				op, _ := fl.uint(3)
				status, body := uint64(2), (*value)(nil)
				if v == AgentVersion {
					status, body = f.handler(op, fl.opt(4))
				}
				keys := []uint64{1, 2, 3}
				vals := []value{vUint(AgentVersion), vUint(id), vUint(status)}
				if body != nil {
					keys = append(keys, 4)
					vals = append(vals, *body)
				}
				out, err := encode(vMap(keys, vals))
				if err != nil {
					return
				}
				if writeFrame(conn, out) != nil {
					return
				}
			}
		}()
	}
}

func m(keys []uint64, vals ...value) *value {
	v := vMap(keys, vals)
	return &v
}

func dial(t *testing.T, f *fakeCore) *Client {
	c, err := Dial(f.path)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	t.Cleanup(func() { c.Close() })
	return c
}

func TestStatusEnrolJoin(t *testing.T) {
	f := newFakeCore(t, func(op uint64, args *value) (uint64, *value) {
		switch op {
		case opAgentStatus:
			if args != nil {
				return 1, nil
			}
			return 0, m([]uint64{1, 2, 3, 4, 5, 6}, vBool(true), vBytes(id(1)), vBytes(id(2)),
				vArray([]value{vBytes(id(3))}), vBytes(id(4)), vUint(42))
		case opAgentEnrol:
			return 0, m([]uint64{1, 2}, vBytes([]byte{0xa0}), vText([]byte("ABCDEFGHIJKLMNOPQRST")))
		case opAgentJoin:
			fl, err := asFields(args, 1, 2)
			if err != nil {
				return 1, nil
			}
			if _, err := fl.fixed(1, 16); err != nil {
				return 1, nil
			}
			if g := fl.opt(2); g != nil && len(g.b) != 48 {
				return 1, nil
			}
			return 0, nil
		}
		return 3, nil
	})
	c := dial(t, f)
	s, err := c.AgentStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enrolled || !bytes.Equal(s.Member, id(1)) || len(s.Lockers) != 1 || s.StartedMs != 42 {
		t.Fatalf("status %+v", s)
	}
	e, err := c.Enrol()
	if err != nil || e.ControlCode != "ABCDEFGHIJKLMNOPQRST" {
		t.Fatalf("enrol %v %+v", err, e)
	}
	if err := c.Join(id(3), nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Join(id(3), bytes.Repeat([]byte{1}, 48)); err != nil {
		t.Fatal(err)
	}
	// Bad inputs are refused before anything is sent.
	n := f.count()
	var e2 *Error
	if err := c.Join(id(3)[:15], nil); !errors.As(err, &e2) || e2.Code != CodeInvalidInput {
		t.Fatalf("short locker: %v", err)
	}
	if err := c.Join(id(3), []byte{1}); err == nil {
		t.Fatal("short genesis accepted")
	}
	if _, err := c.OpenSession(make([]byte, MaxGrant+1)); err == nil {
		t.Fatal("oversized grant accepted")
	}
	if f.count() != n {
		t.Fatal("invalid requests were sent")
	}
}

func TestSessionAndWipe(t *testing.T) {
	grant := []byte("opaque grant bytes")
	f := newFakeCore(t, func(op uint64, args *value) (uint64, *value) {
		if op != opSessionOpen {
			return 3, nil
		}
		fl, err := asFields(args, 1)
		if err != nil {
			return 1, nil
		}
		g, err := fl.bytes(1, MaxGrant)
		if err != nil || !bytes.Equal(g, grant) {
			return 32, m([]uint64{1}, vUint(2))
		}
		return 0, m([]uint64{1, 2, 3},
			vMap([]uint64{10, 11}, []value{vText([]byte("root")), vText([]byte("S3cr3t!"))}),
			vArray([]value{vText([]byte("ssh://root@db.internal:22"))}),
			vArray(nil))
	})
	c := dial(t, f)
	cred, err := c.OpenSession(grant)
	if err != nil {
		t.Fatal(err)
	}
	pw := cred.Fields[FieldPassword]
	if string(pw) != "S3cr3t!" || string(cred.Fields[FieldUsername]) != "root" {
		t.Fatal("wrong credentials")
	}
	if len(cred.URLs) != 1 || cred.URLs[0] != "ssh://root@db.internal:22" {
		t.Fatalf("urls %v", cred.URLs)
	}
	cred.Wipe()
	if !bytes.Equal(pw, make([]byte, len(pw))) || len(cred.Fields) != 0 {
		t.Fatal("not wiped")
	}
	// A refused grant: the reason is reported, no secret.
	_, err = c.OpenSession([]byte("forged"))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeGrantRefused || e.Reason != ReasonBadSignature {
		t.Fatalf("got %v", err)
	}
	if e.Error() != "hirzla: grant refused (bad_signature)" {
		t.Fatalf("message %q", e.Error())
	}
}

func TestIngestOutboxAckRotate(t *testing.T) {
	op := []byte{1, 2, 3}
	opID := bytes.Repeat([]byte{7}, 48)
	f := newFakeCore(t, func(code uint64, args *value) (uint64, *value) {
		switch code {
		case opAgentIngest:
			fl, _ := asFields(args, 1, 2)
			ops, err := fl.array(2, MaxOps)
			if err != nil {
				return 1, nil
			}
			return 0, m([]uint64{1, 2}, vUint(uint64(len(ops))), vUint(0))
		case opAgentOutbox:
			return 0, m([]uint64{1}, vArray([]value{*m([]uint64{1, 2}, vBytes(opID), vBytes(op))}))
		case opAgentAck:
			return 0, nil
		case opRotate:
			return 0, m([]uint64{1, 2}, vBytes(opID), vBool(true))
		}
		return 3, nil
	})
	c := dial(t, f)
	added, dup, err := c.Ingest(id(1), [][]byte{op, op})
	if err != nil || added != 2 || dup != 0 {
		t.Fatalf("ingest %d %d %v", added, dup, err)
	}
	out, err := c.Outbox(id(1))
	if err != nil || len(out) != 1 || !bytes.Equal(out[0].Op, op) {
		t.Fatalf("outbox %v %v", out, err)
	}
	if err := c.Ack(id(1), [][]byte{out[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(id(1), [][]byte{{1}}); err == nil {
		t.Fatal("short id accepted")
	}
	r, err := c.Rotate([]byte("rotation grant"))
	if err != nil || !r.Confirmed || !bytes.Equal(r.Op, opID) {
		t.Fatalf("rotate %+v %v", r, err)
	}
}

func TestMalformedRepliesAreRefused(t *testing.T) {
	replies := []func() *value{
		// Unknown key in the body.
		func() *value { return m([]uint64{1, 2, 3}, vUint(1), vUint(1), vUint(1)) },
		// Wrong type.
		func() *value { return m([]uint64{1}, vText([]byte("x"))) },
	}
	for i, body := range replies {
		f := newFakeCore(t, func(op uint64, args *value) (uint64, *value) { return 0, body() })
		c := dial(t, f)
		if _, err := c.Rotate([]byte("g")); err != ErrMalformed {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// A body on an operation that returns none.
	f := newFakeCore(t, func(op uint64, args *value) (uint64, *value) {
		return 0, m([]uint64{1}, vUint(1))
	})
	if err := dial(t, f).Join(id(1), nil); err != ErrMalformed {
		t.Errorf("join with body: %v", err)
	}
	// A grant refusal without its reason.
	f = newFakeCore(t, func(op uint64, args *value) (uint64, *value) { return 32, nil })
	if _, err := dial(t, f).OpenSession([]byte("g")); err != ErrMalformed {
		t.Errorf("refusal without reason: %v", err)
	}
	// A session with a field the API never returns (title).
	f = newFakeCore(t, func(op uint64, args *value) (uint64, *value) {
		return 0, m([]uint64{1, 2, 3}, vMap([]uint64{1}, []value{vText([]byte("t"))}), vArray(nil), vArray(nil))
	})
	if _, err := dial(t, f).OpenSession([]byte("g")); err != ErrMalformed {
		t.Errorf("unexpected field: %v", err)
	}
}

func TestReplyEnvelopeIsChecked(t *testing.T) {
	path := filepath.Join(privateDir(t), "core.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	replies := [][]value{
		{vUint(1), vUint(1), vUint(0)},  // version 1
		{vUint(3), vUint(99), vUint(0)}, // another identifier
	}
	go func() {
		for _, r := range replies {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if _, err := readFrame(conn); err == nil {
				out, _ := encode(vMap([]uint64{1, 2, 3}, r))
				_ = writeFrame(conn, out)
			}
			conn.Close()
		}
	}()
	for i := range replies {
		c, err := Dial(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.AgentStatus(); err != ErrMalformed {
			t.Errorf("case %d: %v", i, err)
		}
		c.Close()
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, nil); err != ErrMalformed {
		t.Error("empty frame written")
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 0})); err != ErrMalformed {
		t.Error("empty frame read")
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0x80, 0, 1})); err != ErrMalformed {
		t.Error("oversized frame read")
	}
	if err := writeFrame(&buf, []byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0, 0, 0, 1, 0xa0}) {
		t.Fatal("frame layout")
	}
}

func TestDialRefusesUnsafeEndpoints(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(filepath.Join(d, "core.sock")); err != ErrUnsafeEndpoint {
		t.Errorf("open directory: %v", err)
	}
	priv := privateDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(priv, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(filepath.Join(link, "core.sock")); err != ErrUnsafeEndpoint {
		t.Errorf("symbolic link: %v", err)
	}
	if _, err := Dial("relative/core.sock"); err != ErrUnsafeEndpoint {
		t.Errorf("relative path: %v", err)
	}
}
