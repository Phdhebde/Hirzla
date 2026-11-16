package hirzla

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The session grant body of docs/integration-hornn.md § 3.4, as hirzla-access encodes it
// (crates/hirzla-access/src/hornn/tests.rs, fixed_vector_of_the_body). The SDK never builds
// grants; this checks that both encoders agree on the profile.
const grantVector = "ac0101025001010101010101010101010101010101035002020202020202020202020202020202" +
	"045003030303030303030303030303030303055004040404040404040404040404040404" +
	"065005050505050505050505050505050505075006060606060606060606060606060606" +
	"08500707070707070707070707070707070709010a1b000001a3185c50000b1b000001a3185d3a60" +
	"0c820a0b"

func id(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func TestEncoderMatchesTheCore(t *testing.T) {
	const now = 1_800_000_000_000
	// Keys given out of order: the encoder sorts them.
	v := vMap(
		[]uint64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		[]value{
			vArray([]value{vUint(10), vUint(11)}),
			vUint(now + 60_000), vUint(now), vUint(1),
			vBytes(id(7)), vBytes(id(6)), vBytes(id(5)), vBytes(id(4)),
			vBytes(id(3)), vBytes(id(2)), vBytes(id(1)), vUint(1),
		},
	)
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != grantVector {
		t.Fatalf("encoding differs:\n%s\n%s", got, grantVector)
	}
	back, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := encode(back)
	if !bytes.Equal(again, b) {
		t.Fatal("round trip differs")
	}
}

func TestRequestEncodingMatchesTheCore(t *testing.T) {
	// AgentRequest::SessionOpen { grant: [9; 10] }.encode(3) in hirzla-core.
	g := bytes.Repeat([]byte{9}, 10)
	b, err := encode(vMap([]uint64{1, 2, 3, 4}, []value{
		vUint(3), vUint(3), vUint(26), vMap([]uint64{1}, []value{vBytes(g)}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := "a40103020303181a04a1014a" + strings.Repeat("09", 10)
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDecodingIsStrict(t *testing.T) {
	deep := strings.Repeat("81", 17) + "00"
	cases := map[string]string{
		"non-shortest integer":   "1801",
		"non-shortest length":    "5801ff",
		"unsorted keys":          "a2020001 00",
		"duplicate keys":         "a201000100",
		"indefinite array":       "9f00ff",
		"indefinite bytes":       "5f40ff",
		"float":                  "f93c00",
		"tag":                    "c000",
		"negative integer":       "20",
		"null":                   "f6",
		"undefined":              "f7",
		"text map key":           "a1616100",
		"trailing bytes":         "0000",
		"invalid utf-8":          "62c328",
		"truncated":              "43aabb",
		"empty":                  "",
		"too deep":               deep,
		"length beyond input":    "9b00000000ffffffff",
		"reserved additional 28": "1c",
	}
	for name, h := range cases {
		b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		if err != nil {
			t.Fatalf("%s: bad test hex", name)
		}
		if _, err := decode(b); err != ErrMalformed {
			t.Errorf("%s: accepted", name)
		}
	}
	// The limit itself is accepted.
	ok, _ := hex.DecodeString(strings.Repeat("81", 16) + "00")
	if _, err := decode(ok); err != nil {
		t.Errorf("depth 16 refused: %v", err)
	}
}

func TestEncoderRefusesBadInput(t *testing.T) {
	if _, err := encode(vText([]byte{0xff})); err == nil {
		t.Error("invalid UTF-8 encoded")
	}
	if _, err := encode(vMap([]uint64{1, 1}, []value{vUint(0), vUint(0)})); err == nil {
		t.Error("duplicate key encoded")
	}
}

func TestWipe(t *testing.T) {
	s := []byte("secret")
	v := vArray([]value{vText(s), vMap([]uint64{1}, []value{vBytes(s[:3])})})
	v.wipe()
	if !bytes.Equal(s, make([]byte, 6)) {
		t.Fatal("not wiped")
	}
}
