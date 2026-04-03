package vtcp

import (
	"encoding/binary"
	"testing"
)

func TestParseMSSOption(t *testing.T) {
	// Kind=2, Len=4, MSS=1460
	raw := []byte{2, 4, 0x05, 0xB4}
	opts := ParseOptions(raw)
	if len(opts) != 1 {
		t.Fatalf("expected 1 option, got %d", len(opts))
	}
	mss := GetMSS(opts)
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460", mss)
	}
}

func TestParseWScaleOption(t *testing.T) {
	raw := []byte{OptNOP, OptWScale, 3, 7}
	opts := ParseOptions(raw)
	ws := GetWScale(opts)
	if ws != 7 {
		t.Errorf("WScale = %d, want 7", ws)
	}
}

func TestParseTimestampOption(t *testing.T) {
	raw := make([]byte, 10)
	raw[0] = OptTimestamp
	raw[1] = 10
	binary.BigEndian.PutUint32(raw[2:6], 12345)
	binary.BigEndian.PutUint32(raw[6:10], 67890)
	opts := ParseOptions(raw)
	tsVal, tsEcr, ok := GetTimestamp(opts)
	if !ok {
		t.Fatal("timestamp not found")
	}
	if tsVal != 12345 || tsEcr != 67890 {
		t.Errorf("timestamps = (%d, %d), want (12345, 67890)", tsVal, tsEcr)
	}
}

func TestParseSACKPermOption(t *testing.T) {
	raw := []byte{OptSACKPerm, 2}
	opts := ParseOptions(raw)
	if !HasSACKPerm(opts) {
		t.Error("SACK-Permitted not found")
	}
}

func TestParseSACKOption(t *testing.T) {
	raw := make([]byte, 18)
	raw[0] = OptSACK
	raw[1] = 18 // 2 + 2*8
	binary.BigEndian.PutUint32(raw[2:6], 100)
	binary.BigEndian.PutUint32(raw[6:10], 200)
	binary.BigEndian.PutUint32(raw[10:14], 300)
	binary.BigEndian.PutUint32(raw[14:18], 400)
	opts := ParseOptions(raw)
	blocks := GetSACKBlocks(opts)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 SACK blocks, got %d", len(blocks))
	}
	if blocks[0].Left != 100 || blocks[0].Right != 200 {
		t.Errorf("block[0] = (%d,%d), want (100,200)", blocks[0].Left, blocks[0].Right)
	}
	if blocks[1].Left != 300 || blocks[1].Right != 400 {
		t.Errorf("block[1] = (%d,%d), want (300,400)", blocks[1].Left, blocks[1].Right)
	}
}

func TestParseEndOfOptions(t *testing.T) {
	raw := []byte{OptMSS, 4, 0x05, 0xB4, OptEnd, 0xFF, 0xFF}
	opts := ParseOptions(raw)
	if len(opts) != 1 {
		t.Errorf("expected 1 option (End should stop parsing), got %d", len(opts))
	}
}

func TestParseNOPPadding(t *testing.T) {
	raw := []byte{OptNOP, OptNOP, OptMSS, 4, 0x05, 0xB4}
	opts := ParseOptions(raw)
	if len(opts) != 3 {
		t.Fatalf("expected 3 options (2 NOP + MSS), got %d", len(opts))
	}
	mss := GetMSS(opts)
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460", mss)
	}
}

func TestBuildOptions(t *testing.T) {
	opts := []Option{
		MSSOption(1460),
		WScaleOption(7),
		SACKPermOption(),
	}
	raw := BuildOptions(opts)

	// Parse back
	parsed := ParseOptions(raw)
	mss := GetMSS(parsed)
	if mss != 1460 {
		t.Errorf("round-trip MSS = %d, want 1460", mss)
	}
	ws := GetWScale(parsed)
	if ws != 7 {
		t.Errorf("round-trip WScale = %d, want 7", ws)
	}
	if !HasSACKPerm(parsed) {
		t.Error("round-trip SACK-Permitted missing")
	}

	// Must be 4-byte aligned
	if len(raw)%4 != 0 {
		t.Errorf("options length %d not 4-byte aligned", len(raw))
	}
}

func TestBuildTimestampOption(t *testing.T) {
	opt := TimestampOption(100, 200)
	raw := BuildOptions([]Option{opt})
	parsed := ParseOptions(raw)
	tsVal, tsEcr, ok := GetTimestamp(parsed)
	if !ok {
		t.Fatal("timestamp not found after round-trip")
	}
	if tsVal != 100 || tsEcr != 200 {
		t.Errorf("round-trip timestamps = (%d, %d), want (100, 200)", tsVal, tsEcr)
	}
}

func TestBuildSACKOption(t *testing.T) {
	blocks := []SACKBlock{{Left: 1000, Right: 2000}, {Left: 3000, Right: 4000}}
	opt := SACKOption(blocks)
	raw := BuildOptions([]Option{opt})
	parsed := ParseOptions(raw)
	got := GetSACKBlocks(parsed)
	if len(got) != 2 {
		t.Fatalf("round-trip SACK blocks = %d, want 2", len(got))
	}
	if got[0].Left != 1000 || got[0].Right != 2000 {
		t.Errorf("block[0] = (%d,%d), want (1000,2000)", got[0].Left, got[0].Right)
	}
}

func TestParseEmpty(t *testing.T) {
	opts := ParseOptions(nil)
	if len(opts) != 0 {
		t.Errorf("expected 0 options from nil, got %d", len(opts))
	}
	opts = ParseOptions([]byte{})
	if len(opts) != 0 {
		t.Errorf("expected 0 options from empty, got %d", len(opts))
	}
}

func TestGetMSSNotPresent(t *testing.T) {
	if GetMSS(nil) != 0 {
		t.Error("GetMSS(nil) should return 0")
	}
}

func TestGetWScaleNotPresent(t *testing.T) {
	if GetWScale(nil) != -1 {
		t.Error("GetWScale(nil) should return -1")
	}
}

func TestGetTimestampNotPresent(t *testing.T) {
	_, _, ok := GetTimestamp(nil)
	if ok {
		t.Error("GetTimestamp(nil) should return ok=false")
	}
}
