package hirzla

// Deterministic CBOR in the profile of docs/format.md § 2.1, restricted to what the local
// API carries: unsigned integers, byte strings, text strings, arrays, maps with unsigned
// integer keys, booleans. This is a data encoding, not cryptography: the SDK never signs,
// encrypts or verifies anything (the core does).
//
// Decoding is strict, like the core's: it refuses floats, tags, negative integers,
// indefinite lengths, nesting deeper than 16, invalid UTF-8, then re-encodes the value and
// compares the bytes, which refuses non-shortest integers, unsorted or duplicated keys and
// trailing bytes.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf8"
)

const (
	maxDepth = 16
	maxItems = 1 << 20
)

// ErrMalformed reports a frame or a value outside the protocol.
var ErrMalformed = errors.New("hirzla: malformed message")

// kind of a decoded value.
type kind uint8

const (
	kUint kind = iota
	kBytes
	kText
	kArray
	kMap
	kBool
)

// value is one CBOR item. Byte and text strings are kept as []byte so that a secret can be
// erased (see wipe).
type value struct {
	k     kind
	u     uint64
	b     []byte // bytes and text
	items []value
	keys  []uint64 // map keys, parallel to items
	t     bool
}

func vUint(u uint64) value   { return value{k: kUint, u: u} }
func vBytes(b []byte) value  { return value{k: kBytes, b: b} }
func vText(s []byte) value   { return value{k: kText, b: s} }
func vBool(t bool) value     { return value{k: kBool, t: t} }
func vArray(v []value) value { return value{k: kArray, items: v} }

// vMap builds a map; keys are sorted on encoding.
func vMap(keys []uint64, vals []value) value {
	return value{k: kMap, keys: keys, items: vals}
}

// wipe zeroes every string held by v.
func (v *value) wipe() {
	clear(v.b)
	for i := range v.items {
		v.items[i].wipe()
	}
}

func head(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.WriteByte(m | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	default:
		buf.WriteByte(m | 27)
		_ = binary.Write(buf, binary.BigEndian, n)
	}
}

func encodeTo(buf *bytes.Buffer, v value) error {
	switch v.k {
	case kUint:
		head(buf, 0, v.u)
	case kBytes:
		head(buf, 2, uint64(len(v.b)))
		buf.Write(v.b)
	case kText:
		if !utf8.Valid(v.b) {
			return ErrMalformed
		}
		head(buf, 3, uint64(len(v.b)))
		buf.Write(v.b)
	case kArray:
		head(buf, 4, uint64(len(v.items)))
		for _, it := range v.items {
			if err := encodeTo(buf, it); err != nil {
				return err
			}
		}
	case kMap:
		if len(v.keys) != len(v.items) {
			return ErrMalformed
		}
		idx := make([]int, len(v.keys))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return v.keys[idx[a]] < v.keys[idx[b]] })
		for i := 1; i < len(idx); i++ {
			if v.keys[idx[i]] == v.keys[idx[i-1]] {
				return ErrMalformed
			}
		}
		head(buf, 5, uint64(len(v.keys)))
		for _, i := range idx {
			head(buf, 0, v.keys[i])
			if err := encodeTo(buf, v.items[i]); err != nil {
				return err
			}
		}
	case kBool:
		if v.t {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	default:
		return ErrMalformed
	}
	return nil
}

// encode returns the deterministic encoding of v.
func encode(v value) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeTo(&buf, v); err != nil {
		clear(buf.Bytes())
		return nil, err
	}
	return buf.Bytes(), nil
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) arg(info byte) (uint64, error) {
	need := 0
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		need = 1
	case info == 25:
		need = 2
	case info == 26:
		need = 4
	case info == 27:
		need = 8
	default:
		return 0, ErrMalformed
	}
	if len(r.b)-r.pos < need {
		return 0, ErrMalformed
	}
	var n uint64
	for _, c := range r.b[r.pos : r.pos+need] {
		n = n<<8 | uint64(c)
	}
	r.pos += need
	return n, nil
}

func (r *reader) read(depth int) (value, error) {
	if depth > maxDepth || r.pos >= len(r.b) {
		return value{}, ErrMalformed
	}
	first := r.b[r.pos]
	r.pos++
	major, info := first>>5, first&0x1f
	if major == 7 {
		switch first {
		case 0xf4:
			return vBool(false), nil
		case 0xf5:
			return vBool(true), nil
		default:
			return value{}, ErrMalformed
		}
	}
	n, err := r.arg(info)
	if err != nil {
		return value{}, err
	}
	switch major {
	case 0:
		return vUint(n), nil
	case 2, 3:
		if n > uint64(len(r.b)-r.pos) {
			return value{}, ErrMalformed
		}
		s := make([]byte, n)
		copy(s, r.b[r.pos:r.pos+int(n)])
		r.pos += int(n)
		if major == 3 {
			if !utf8.Valid(s) {
				return value{}, ErrMalformed
			}
			return vText(s), nil
		}
		return vBytes(s), nil
	case 4:
		if n > maxItems || n > uint64(len(r.b)-r.pos) {
			return value{}, ErrMalformed
		}
		items := make([]value, 0, n)
		for i := uint64(0); i < n; i++ {
			it, err := r.read(depth + 1)
			if err != nil {
				return value{}, err
			}
			items = append(items, it)
		}
		return vArray(items), nil
	case 5:
		if n > maxItems || n > uint64(len(r.b)-r.pos) {
			return value{}, ErrMalformed
		}
		keys := make([]uint64, 0, n)
		vals := make([]value, 0, n)
		for i := uint64(0); i < n; i++ {
			k, err := r.read(depth + 1)
			if err != nil || k.k != kUint {
				return value{}, ErrMalformed
			}
			v, err := r.read(depth + 1)
			if err != nil {
				return value{}, err
			}
			keys = append(keys, k.u)
			vals = append(vals, v)
		}
		return vMap(keys, vals), nil
	default:
		// Negative integers and tags are outside what the API carries.
		return value{}, ErrMalformed
	}
}

// decode reads exactly one canonical item from b.
func decode(b []byte) (value, error) {
	r := reader{b: b}
	v, err := r.read(0)
	if err != nil {
		return value{}, err
	}
	if r.pos != len(b) {
		v.wipe()
		return value{}, ErrMalformed
	}
	again, err := encode(v)
	if err != nil || !bytes.Equal(again, b) {
		clear(again)
		v.wipe()
		return value{}, ErrMalformed
	}
	clear(again)
	return v, nil
}

// fields gives typed access to a decoded map whose keys must be among allowed.
type fields struct {
	m map[uint64]*value
}

func asFields(v *value, allowed ...uint64) (fields, error) {
	if v == nil || v.k != kMap {
		return fields{}, ErrMalformed
	}
	f := fields{m: make(map[uint64]*value, len(v.keys))}
	for i, k := range v.keys {
		ok := false
		for _, a := range allowed {
			if a == k {
				ok = true
				break
			}
		}
		if !ok {
			return fields{}, ErrMalformed
		}
		f.m[k] = &v.items[i]
	}
	return f, nil
}

func (f fields) opt(k uint64) *value { return f.m[k] }

func (f fields) uint(k uint64) (uint64, error) {
	v := f.m[k]
	if v == nil || v.k != kUint {
		return 0, ErrMalformed
	}
	return v.u, nil
}

func (f fields) bool(k uint64) (bool, error) {
	v := f.m[k]
	if v == nil || v.k != kBool {
		return false, ErrMalformed
	}
	return v.t, nil
}

func (f fields) bytes(k uint64, max int) ([]byte, error) {
	v := f.m[k]
	if v == nil || v.k != kBytes || len(v.b) > max {
		return nil, ErrMalformed
	}
	return v.b, nil
}

func (f fields) fixed(k uint64, n int) ([]byte, error) {
	b, err := f.bytes(k, n)
	if err != nil || len(b) != n {
		return nil, ErrMalformed
	}
	return b, nil
}

func (f fields) text(k uint64, max int) ([]byte, error) {
	v := f.m[k]
	if v == nil || v.k != kText || len(v.b) > max {
		return nil, ErrMalformed
	}
	return v.b, nil
}

func (f fields) array(k uint64, max int) ([]value, error) {
	v := f.m[k]
	if v == nil || v.k != kArray || len(v.items) > max {
		return nil, ErrMalformed
	}
	return v.items, nil
}
