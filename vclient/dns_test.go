package vclient

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestEncodeDNSName(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"a.b.c", []byte{1, 'a', 1, 'b', 1, 'c', 0}},
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}}, // trailing dot stripped
		{"localhost", []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0}},
	}
	for _, tt := range tests {
		got := encodeDNSName(tt.name)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("encodeDNSName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q := buildDNSQuery(0x1234, "example.com", 1)

	// Check header
	if len(q) < 12 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	id := binary.BigEndian.Uint16(q[0:2])
	if id != 0x1234 {
		t.Errorf("ID = 0x%04x, want 0x1234", id)
	}
	if q[2] != 0x01 { // RD bit
		t.Errorf("flags byte 0 = 0x%02x, want 0x01", q[2])
	}
	qdcount := binary.BigEndian.Uint16(q[4:6])
	if qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}

	// Question section: encoded name + QTYPE(2) + QCLASS(2)
	name := encodeDNSName("example.com")
	nameStart := 12
	nameEnd := nameStart + len(name)
	if nameEnd+4 > len(q) {
		t.Fatalf("query too short for question section")
	}
	if !bytes.Equal(q[nameStart:nameEnd], name) {
		t.Errorf("question name mismatch")
	}
	qtype := binary.BigEndian.Uint16(q[nameEnd : nameEnd+2])
	if qtype != 1 {
		t.Errorf("QTYPE = %d, want 1 (A)", qtype)
	}
	qclass := binary.BigEndian.Uint16(q[nameEnd+2 : nameEnd+4])
	if qclass != 1 {
		t.Errorf("QCLASS = %d, want 1 (IN)", qclass)
	}
}

func TestSkipDNSName(t *testing.T) {
	// Normal labels: 3 "www" 7 "example" 3 "com" 0
	data := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	off := skipDNSName(data, 0)
	if off != len(data) {
		t.Errorf("skipDNSName normal = %d, want %d", off, len(data))
	}

	// Compression pointer: 0xC0 0x00 (pointer to offset 0)
	data2 := []byte{0xC0, 0x00}
	off2 := skipDNSName(data2, 0)
	if off2 != 2 {
		t.Errorf("skipDNSName pointer = %d, want 2", off2)
	}

	// Out of bounds
	off3 := skipDNSName([]byte{}, 0)
	if off3 != -1 {
		t.Errorf("skipDNSName empty = %d, want -1", off3)
	}

	off4 := skipDNSName([]byte{5, 'h', 'e'}, 0) // label says 5 but only 2 bytes follow
	if off4 != -1 {
		t.Errorf("skipDNSName truncated = %d, want -1", off4)
	}
}

// buildTestDNSResponse constructs a minimal DNS response with A records.
func buildTestDNSResponse(id uint16, name string, ips []net.IP) []byte {
	var buf []byte

	// Header
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)           // QR=1, RD=1, RA=1, RCODE=0
	binary.BigEndian.PutUint16(hdr[4:6], 1)                // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(ips))) // ANCOUNT
	buf = append(buf, hdr...)

	// Question section
	qname := encodeDNSName(name)
	buf = append(buf, qname...)
	var qfoot [4]byte
	binary.BigEndian.PutUint16(qfoot[0:2], 1) // A
	binary.BigEndian.PutUint16(qfoot[2:4], 1) // IN
	buf = append(buf, qfoot[:]...)

	// Answer section
	for _, ip := range ips {
		ip4 := ip.To4()
		// Use compression pointer to question name
		buf = append(buf, 0xC0, 12) // pointer to offset 12
		var rec [10]byte
		binary.BigEndian.PutUint16(rec[0:2], 1)   // TYPE A
		binary.BigEndian.PutUint16(rec[2:4], 1)   // CLASS IN
		binary.BigEndian.PutUint32(rec[4:8], 300) // TTL
		binary.BigEndian.PutUint16(rec[8:10], 4)  // RDLENGTH
		buf = append(buf, rec[:]...)
		buf = append(buf, ip4...)
	}

	return buf
}

func TestParseDNSResponse(t *testing.T) {
	// Valid response with two A records
	resp := buildTestDNSResponse(0xABCD, "example.com", []net.IP{
		net.IPv4(1, 2, 3, 4),
		net.IPv4(5, 6, 7, 8),
	})
	ips, err := parseDNSResponse(resp, 0xABCD)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %d IPs, want 2", len(ips))
	}
	if !ips[0].Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("ip[0] = %v, want 1.2.3.4", ips[0])
	}
	if !ips[1].Equal(net.IPv4(5, 6, 7, 8)) {
		t.Errorf("ip[1] = %v, want 5.6.7.8", ips[1])
	}
}

func TestParseDNSResponseIDMismatch(t *testing.T) {
	resp := buildTestDNSResponse(0x0001, "example.com", []net.IP{net.IPv4(1, 2, 3, 4)})
	_, err := parseDNSResponse(resp, 0x9999)
	if err == nil {
		t.Error("expected ID mismatch error")
	}
}

func TestParseDNSResponseTooShort(t *testing.T) {
	_, err := parseDNSResponse([]byte{0, 1, 2}, 0)
	if err == nil {
		t.Error("expected too-short error")
	}
}

func TestParseDNSResponseNotResponse(t *testing.T) {
	// QR bit = 0 (query, not response)
	resp := buildTestDNSResponse(0x1234, "x.com", []net.IP{net.IPv4(1, 1, 1, 1)})
	resp[2] = 0x01 // clear QR bit
	resp[3] = 0x00
	_, err := parseDNSResponse(resp, 0x1234)
	if err == nil {
		t.Error("expected not-a-response error")
	}
}

func TestParseDNSResponseRcodeError(t *testing.T) {
	resp := buildTestDNSResponse(0x1234, "x.com", nil)
	resp[3] = resp[3] | 0x03 // NXDOMAIN
	_, err := parseDNSResponse(resp, 0x1234)
	if err == nil {
		t.Error("expected RCODE error")
	}
}

func TestParseDNSResponseNoAnswers(t *testing.T) {
	resp := buildTestDNSResponse(0x1234, "example.com", nil)
	ips, err := parseDNSResponse(resp, 0x1234)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("got %d IPs, want 0", len(ips))
	}
}

func TestParseDNSResponseMalformedQuestion(t *testing.T) {
	// Header claims 1 question, but question data is truncated
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8000) // QR=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT = 1
	// Only append partial label - no terminating zero and no QTYPE/QCLASS
	data := append(hdr, 5, 'h', 'e', 'l', 'l')
	_, err := parseDNSResponse(data, 0x1234)
	if err == nil {
		t.Error("expected malformed question error")
	}
}
