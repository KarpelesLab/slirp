package vtcp

import (
	"encoding/binary"
	"testing"
)

func TestParseSegmentMinimal(t *testing.T) {
	// Build a minimal 20-byte TCP header
	raw := make([]byte, 20)
	binary.BigEndian.PutUint16(raw[0:2], 12345)   // src port
	binary.BigEndian.PutUint16(raw[2:4], 80)      // dst port
	binary.BigEndian.PutUint32(raw[4:8], 1000)    // seq
	binary.BigEndian.PutUint32(raw[8:12], 2000)   // ack
	raw[12] = 5 << 4                              // data offset = 5 (20 bytes)
	raw[13] = FlagSYN | FlagACK                   // flags
	binary.BigEndian.PutUint16(raw[14:16], 65535) // window

	seg, err := ParseSegment(raw)
	if err != nil {
		t.Fatalf("ParseSegment: %v", err)
	}
	if seg.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", seg.SrcPort)
	}
	if seg.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", seg.DstPort)
	}
	if seg.Seq != 1000 {
		t.Errorf("Seq = %d, want 1000", seg.Seq)
	}
	if seg.Ack != 2000 {
		t.Errorf("Ack = %d, want 2000", seg.Ack)
	}
	if seg.Flags != FlagSYN|FlagACK {
		t.Errorf("Flags = 0x%02x, want 0x%02x", seg.Flags, FlagSYN|FlagACK)
	}
	if seg.Window != 65535 {
		t.Errorf("Window = %d, want 65535", seg.Window)
	}
	if len(seg.Options) != 0 {
		t.Errorf("Options = %d, want 0", len(seg.Options))
	}
	if len(seg.Payload) != 0 {
		t.Errorf("Payload = %d bytes, want 0", len(seg.Payload))
	}
}

func TestParseSegmentWithPayload(t *testing.T) {
	raw := make([]byte, 25) // 20 header + 5 payload
	raw[12] = 5 << 4
	raw[13] = FlagACK | FlagPSH
	copy(raw[20:], []byte("hello"))

	seg, err := ParseSegment(raw)
	if err != nil {
		t.Fatalf("ParseSegment: %v", err)
	}
	if string(seg.Payload) != "hello" {
		t.Errorf("Payload = %q, want %q", seg.Payload, "hello")
	}
}

func TestParseSegmentWithOptions(t *testing.T) {
	// 20 base + 4 MSS option = 24 bytes, data offset = 6
	raw := make([]byte, 24)
	raw[12] = 6 << 4
	raw[13] = FlagSYN
	// MSS option at offset 20
	raw[20] = OptMSS
	raw[21] = 4
	binary.BigEndian.PutUint16(raw[22:24], 1460)

	seg, err := ParseSegment(raw)
	if err != nil {
		t.Fatalf("ParseSegment: %v", err)
	}
	mss := GetMSS(seg.Options)
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460", mss)
	}
}

func TestParseSegmentTooShort(t *testing.T) {
	_, err := ParseSegment([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short segment")
	}
}

func TestParseSegmentBadOffset(t *testing.T) {
	raw := make([]byte, 20)
	raw[12] = 15 << 4 // data offset = 60, but segment is only 20 bytes
	_, err := ParseSegment(raw)
	if err == nil {
		t.Error("expected error for bad data offset")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	orig := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		Ack:     2000,
		Flags:   FlagSYN | FlagACK,
		Window:  32768,
		Options: []Option{MSSOption(1460)},
		Payload: []byte("test data"),
	}
	raw := orig.Marshal()
	parsed, err := ParseSegment(raw)
	if err != nil {
		t.Fatalf("ParseSegment: %v", err)
	}
	if parsed.SrcPort != orig.SrcPort {
		t.Errorf("SrcPort = %d, want %d", parsed.SrcPort, orig.SrcPort)
	}
	if parsed.DstPort != orig.DstPort {
		t.Errorf("DstPort = %d, want %d", parsed.DstPort, orig.DstPort)
	}
	if parsed.Seq != orig.Seq {
		t.Errorf("Seq = %d, want %d", parsed.Seq, orig.Seq)
	}
	if parsed.Ack != orig.Ack {
		t.Errorf("Ack = %d, want %d", parsed.Ack, orig.Ack)
	}
	if parsed.Flags != orig.Flags {
		t.Errorf("Flags = 0x%02x, want 0x%02x", parsed.Flags, orig.Flags)
	}
	if parsed.Window != orig.Window {
		t.Errorf("Window = %d, want %d", parsed.Window, orig.Window)
	}
	if string(parsed.Payload) != "test data" {
		t.Errorf("Payload = %q, want %q", parsed.Payload, "test data")
	}
	mss := GetMSS(parsed.Options)
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460", mss)
	}
}

func TestSegLen(t *testing.T) {
	s := Segment{Payload: []byte("hello")}
	if s.SegLen() != 5 {
		t.Errorf("SegLen = %d, want 5", s.SegLen())
	}

	s.Flags = FlagSYN
	if s.SegLen() != 6 {
		t.Errorf("SegLen with SYN = %d, want 6", s.SegLen())
	}

	s.Flags = FlagFIN
	if s.SegLen() != 6 {
		t.Errorf("SegLen with FIN = %d, want 6", s.SegLen())
	}

	s.Flags = FlagSYN | FlagFIN
	if s.SegLen() != 7 {
		t.Errorf("SegLen with SYN+FIN = %d, want 7", s.SegLen())
	}

	s2 := Segment{Flags: FlagSYN}
	if s2.SegLen() != 1 {
		t.Errorf("SYN-only SegLen = %d, want 1", s2.SegLen())
	}
}

func TestHasFlag(t *testing.T) {
	s := Segment{Flags: FlagSYN | FlagACK}
	if !s.HasFlag(FlagSYN) {
		t.Error("should have SYN")
	}
	if !s.HasFlag(FlagACK) {
		t.Error("should have ACK")
	}
	if s.HasFlag(FlagFIN) {
		t.Error("should not have FIN")
	}
}

func TestMarshalNoOptions(t *testing.T) {
	s := Segment{
		SrcPort: 1000,
		DstPort: 2000,
		Seq:     100,
		Ack:     200,
		Flags:   FlagACK,
		Window:  65535,
	}
	raw := s.Marshal()
	if len(raw) != 20 {
		t.Errorf("marshal length = %d, want 20", len(raw))
	}
	// Verify data offset = 5
	if raw[12]>>4 != 5 {
		t.Errorf("data offset = %d, want 5", raw[12]>>4)
	}
}
