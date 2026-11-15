// Package hirzla is a thin client of the Hirzla core for the Hornn agent gateway.
//
// The agent gateway is a machine member of the lockers it serves (docs/integration-hornn.md).
// Its keys, its replicas and every check of a Hornn session grant live in the Hirzla core
// running next to it (hirzla-core started with --hornn-issuer and --hornn-key). This package
// only talks to that core over its local channel (docs/api-locale.md, version 3, operations
// 20 to 27): it implements no cryptography, holds no key, and forwards grants and operations
// as opaque bytes.
//
// The only secrets it ever holds are the credentials of a session, returned by
// OpenSession: call Credentials.Wipe as soon as the connection to the target is open.
package hirzla

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Protocol constants (docs/api-locale.md § 4 and § 13).
const (
	// AgentVersion is the version of the local API that carries the agent operations.
	AgentVersion = 3
	// MaxFrame is the largest frame body, in bytes.
	MaxFrame = 8 * 1024 * 1024
	// MaxGrant is the largest encoded session grant, in bytes.
	MaxGrant = 8 * 1024
	// MaxOps is the most operations in one Ingest or Outbox.
	MaxOps = 1024
	// MaxOpLen is the largest encoded operation, in bytes.
	MaxOpLen = 2 * 1024 * 1024
)

// Operation codes of the agent profile.
const (
	opAgentStatus = 20
	opAgentEnrol  = 21
	opAgentJoin   = 22
	opAgentIngest = 23
	opAgentOutbox = 24
	opAgentAck    = 25
	opSessionOpen = 26
	opRotate      = 27
)

// Client is a connection to the Hirzla core. One request at a time; safe for concurrent
// use (calls are serialised).
type Client struct {
	mu     sync.Mutex
	conn   net.Conn
	nextID uint64
	// Timeout bounds each call; zero means none.
	Timeout time.Duration
}

// Dial connects to the core at the Unix socket path and checks that the endpoint is private
// to the user and, where the system tells, that the process behind it runs under the same
// user (docs/api-locale.md § 3.2).
func Dial(path string) (*Client, error) {
	if err := checkSocketDir(path); err != nil {
		return nil, err
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("hirzla: cannot reach the core: %w", err)
	}
	if err := checkPeer(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{conn: conn, nextID: 1}, nil
}

// NewClient wraps an established connection (tests, or a transport checked by the caller).
func NewClient(conn net.Conn) *Client {
	return &Client{conn: conn, nextID: 1}
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func writeFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxFrame {
		return ErrMalformed
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(body)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, ErrMalformed
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

// call sends one agent request and returns the decoded body of a success (nil if none).
// The caller wipes the returned value when it holds secrets.
func (c *Client) call(op uint64, args *value) (*value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	keys := []uint64{1, 2, 3}
	vals := []value{vUint(AgentVersion), vUint(id), vUint(op)}
	if args != nil {
		keys = append(keys, 4)
		vals = append(vals, *args)
	}
	req, err := encode(vMap(keys, vals))
	if err != nil {
		return nil, err
	}
	if c.Timeout > 0 {
		_ = c.conn.SetDeadline(time.Now().Add(c.Timeout))
		defer c.conn.SetDeadline(time.Time{})
	}
	err = writeFrame(c.conn, req)
	clear(req)
	if err != nil {
		return nil, fmt.Errorf("hirzla: %w", err)
	}
	frame, err := readFrame(c.conn)
	if err != nil {
		if errors.Is(err, ErrMalformed) {
			return nil, err
		}
		return nil, fmt.Errorf("hirzla: %w", err)
	}
	reply, err := decode(frame)
	clear(frame)
	if err != nil {
		return nil, err
	}
	f, err := asFields(&reply, 1, 2, 3, 4)
	if err != nil {
		reply.wipe()
		return nil, err
	}
	v, err1 := f.uint(1)
	rid, err2 := f.uint(2)
	status, err3 := f.uint(3)
	if err1 != nil || err2 != nil || err3 != nil || v != AgentVersion {
		reply.wipe()
		return nil, ErrMalformed
	}
	// A refusal of the connection itself carries identifier 0.
	if rid != id && !(rid == 0 && status != 0) {
		reply.wipe()
		return nil, ErrMalformed
	}
	body := f.opt(4)
	if status != 0 {
		e := &Error{Code: Code(status)}
		if status == uint64(CodeGrantRefused) {
			d, err := asFields(body, 1)
			if err != nil {
				return nil, ErrMalformed
			}
			r, err := d.uint(1)
			if err != nil {
				return nil, ErrMalformed
			}
			e.Reason = GrantReason(r)
		}
		return nil, e
	}
	return body, nil
}
