package vclient

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildDHCPMessageDiscover(t *testing.T) {
	mac := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	c := New(mac, func([]byte) error { return nil })
	defer c.Close()

	msg := c.buildDHCPMessage(dhcpDiscover, 0x12345678, [4]byte{}, [4]byte{})

	// Basic BOOTP fields
	if msg[0] != 1 {
		t.Errorf("op = %d, want 1 (BOOTREQUEST)", msg[0])
	}
	if msg[1] != 1 {
		t.Errorf("htype = %d, want 1 (Ethernet)", msg[1])
	}
	if msg[2] != 6 {
		t.Errorf("hlen = %d, want 6", msg[2])
	}
	xid := binary.BigEndian.Uint32(msg[4:8])
	if xid != 0x12345678 {
		t.Errorf("xid = 0x%08x, want 0x12345678", xid)
	}
	// Broadcast flag
	flags := binary.BigEndian.Uint16(msg[10:12])
	if flags != 0x8000 {
		t.Errorf("flags = 0x%04x, want 0x8000", flags)
	}
	// chaddr
	if msg[28] != 0xAA || msg[29] != 0xBB || msg[30] != 0xCC ||
		msg[31] != 0xDD || msg[32] != 0xEE || msg[33] != 0xFF {
		t.Errorf("chaddr mismatch: got %x", msg[28:34])
	}

	// Magic cookie at offset 236
	if msg[236] != 99 || msg[237] != 130 || msg[238] != 83 || msg[239] != 99 {
		t.Errorf("magic cookie mismatch: %v", msg[236:240])
	}

	// Option 53 (Message Type) = dhcpDiscover (1)
	off := 240
	if msg[off] != dhcpOptMessageType || msg[off+1] != 1 || msg[off+2] != dhcpDiscover {
		t.Errorf("message type option wrong: %v", msg[off:off+3])
	}
	off += 3

	// Discover should NOT have option 50 (Requested IP) or 54 (Server ID)
	// Next should be option 55 (Parameter Request List)
	if msg[off] != dhcpOptParameterList {
		t.Errorf("expected parameter list at offset %d, got option %d", off, msg[off])
	}
}

func TestBuildDHCPMessageRequest(t *testing.T) {
	mac := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	c := New(mac, func([]byte) error { return nil })
	defer c.Close()

	reqIP := [4]byte{10, 0, 0, 100}
	srvIP := [4]byte{10, 0, 0, 1}
	msg := c.buildDHCPMessage(dhcpRequest, 0xDEADBEEF, reqIP, srvIP)

	// Option 53 = dhcpRequest (3)
	off := 240
	if msg[off] != dhcpOptMessageType || msg[off+2] != dhcpRequest {
		t.Errorf("message type = %d, want %d", msg[off+2], dhcpRequest)
	}
	off += 3

	// Option 50: Requested IP
	if msg[off] != dhcpOptRequestedIP {
		t.Fatalf("expected option 50 at offset %d, got %d", off, msg[off])
	}
	if msg[off+1] != 4 {
		t.Fatalf("option 50 length = %d, want 4", msg[off+1])
	}
	var gotReqIP [4]byte
	copy(gotReqIP[:], msg[off+2:off+6])
	if gotReqIP != reqIP {
		t.Errorf("requested IP = %v, want %v", gotReqIP, reqIP)
	}
	off += 6

	// Option 54: Server Identifier
	if msg[off] != dhcpOptServerID {
		t.Fatalf("expected option 54 at offset %d, got %d", off, msg[off])
	}
	var gotSrvIP [4]byte
	copy(gotSrvIP[:], msg[off+2:off+6])
	if gotSrvIP != srvIP {
		t.Errorf("server ID = %v, want %v", gotSrvIP, srvIP)
	}
	off += 6

	// Option 55: Parameter List
	if msg[off] != dhcpOptParameterList {
		t.Errorf("expected option 55, got %d", msg[off])
	}
}

// buildTestDHCPResponse constructs a DHCP response for testing parseDHCPResponse.
func buildTestDHCPResponse(xid uint32, yourIP [4]byte, msgType byte, opts map[byte][]byte) []byte {
	msg := make([]byte, 240)
	msg[0] = 2 // BOOTREPLY
	msg[1] = 1 // Ethernet
	msg[2] = 6
	binary.BigEndian.PutUint32(msg[4:8], xid)
	copy(msg[16:20], yourIP[:])
	// Magic cookie
	msg[236] = 99
	msg[237] = 130
	msg[238] = 83
	msg[239] = 99

	// Add message type option
	msg = append(msg, dhcpOptMessageType, 1, msgType)

	// Add additional options
	for opt, val := range opts {
		msg = append(msg, opt, byte(len(val)))
		msg = append(msg, val...)
	}

	msg = append(msg, dhcpOptEnd)
	return msg
}

func TestParseDHCPResponseOffer(t *testing.T) {
	yourIP := [4]byte{10, 0, 0, 50}
	opts := map[byte][]byte{
		dhcpOptSubnetMask: {255, 255, 255, 0},
		dhcpOptRouter:     {10, 0, 0, 1},
		dhcpOptDNS:        {8, 8, 8, 8, 8, 8, 4, 4}, // two DNS servers
		dhcpOptServerID:   {10, 0, 0, 1},
	}

	data := buildTestDHCPResponse(0xCAFEBABE, yourIP, dhcpOffer, opts)
	resp, err := parseDHCPResponse(data, 0xCAFEBABE)
	if err != nil {
		t.Fatalf("parseDHCPResponse: %v", err)
	}

	if resp.yourIP != yourIP {
		t.Errorf("yourIP = %v, want %v", resp.yourIP, yourIP)
	}
	if resp.msgType != dhcpOffer {
		t.Errorf("msgType = %d, want %d", resp.msgType, dhcpOffer)
	}
	if resp.mask != [4]byte{255, 255, 255, 0} {
		t.Errorf("mask = %v, want 255.255.255.0", resp.mask)
	}
	if resp.router != [4]byte{10, 0, 0, 1} {
		t.Errorf("router = %v, want 10.0.0.1", resp.router)
	}
	if resp.serverIP != [4]byte{10, 0, 0, 1} {
		t.Errorf("serverIP = %v, want 10.0.0.1", resp.serverIP)
	}
	if len(resp.dns) != 2 {
		t.Fatalf("dns count = %d, want 2", len(resp.dns))
	}
	if resp.dns[0] != [4]byte{8, 8, 8, 8} {
		t.Errorf("dns[0] = %v, want 8.8.8.8", resp.dns[0])
	}
	if resp.dns[1] != [4]byte{8, 8, 4, 4} {
		t.Errorf("dns[1] = %v, want 8.8.4.4", resp.dns[1])
	}
}

func TestParseDHCPResponseAck(t *testing.T) {
	data := buildTestDHCPResponse(0x11111111, [4]byte{192, 168, 1, 100}, dhcpAck, nil)
	resp, err := parseDHCPResponse(data, 0x11111111)
	if err != nil {
		t.Fatalf("parseDHCPResponse: %v", err)
	}
	if resp.msgType != dhcpAck {
		t.Errorf("msgType = %d, want %d", resp.msgType, dhcpAck)
	}
	if resp.yourIP != [4]byte{192, 168, 1, 100} {
		t.Errorf("yourIP = %v, want 192.168.1.100", resp.yourIP)
	}
}

func TestParseDHCPResponseTooShort(t *testing.T) {
	_, err := parseDHCPResponse(make([]byte, 100), 0)
	if err == nil {
		t.Error("expected too-short error")
	}
}

func TestParseDHCPResponseNotReply(t *testing.T) {
	data := buildTestDHCPResponse(0x1234, [4]byte{}, dhcpOffer, nil)
	data[0] = 1 // op = BOOTREQUEST (not reply)
	_, err := parseDHCPResponse(data, 0x1234)
	if err == nil {
		t.Error("expected not-reply error")
	}
}

func TestParseDHCPResponseXIDMismatch(t *testing.T) {
	data := buildTestDHCPResponse(0x1111, [4]byte{}, dhcpOffer, nil)
	_, err := parseDHCPResponse(data, 0x9999)
	if err == nil {
		t.Error("expected XID mismatch error")
	}
}

func TestParseDHCPResponseBadMagicCookie(t *testing.T) {
	data := buildTestDHCPResponse(0x1234, [4]byte{10, 0, 0, 1}, dhcpOffer, nil)
	// Corrupt magic cookie
	data[236] = 0
	data[237] = 0
	data[238] = 0
	data[239] = 0
	resp, err := parseDHCPResponse(data, 0x1234)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return response with yourIP but no parsed options
	if resp.yourIP != [4]byte{10, 0, 0, 1} {
		t.Errorf("yourIP = %v, want 10.0.0.1", resp.yourIP)
	}
	if resp.msgType != 0 {
		t.Errorf("msgType = %d, want 0 (no options parsed)", resp.msgType)
	}
}

func TestParseDHCPResponseWithPadding(t *testing.T) {
	// Build a response with padding bytes (option 0) before real options
	msg := make([]byte, 240)
	msg[0] = 2 // BOOTREPLY
	msg[1] = 1
	msg[2] = 6
	binary.BigEndian.PutUint32(msg[4:8], 0x5555)
	// Magic cookie
	msg[236] = 99
	msg[237] = 130
	msg[238] = 83
	msg[239] = 99
	// Padding, then message type, then end
	msg = append(msg, 0, 0, 0) // 3 padding bytes
	msg = append(msg, dhcpOptMessageType, 1, dhcpAck)
	msg = append(msg, dhcpOptEnd)

	resp, err := parseDHCPResponse(msg, 0x5555)
	if err != nil {
		t.Fatalf("parseDHCPResponse with padding: %v", err)
	}
	if resp.msgType != dhcpAck {
		t.Errorf("msgType = %d, want %d (ACK)", resp.msgType, dhcpAck)
	}
}

func TestDHCPResult(t *testing.T) {
	c := New([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, nil)
	defer c.Close()

	c.mu.Lock()
	c.ip = [4]byte{10, 0, 0, 50}
	c.mask = [4]byte{255, 255, 255, 0}
	c.gw = [4]byte{10, 0, 0, 1}
	c.dns = [][4]byte{{8, 8, 8, 8}, {8, 8, 4, 4}}
	c.mu.Unlock()

	result := c.DHCPResult()
	if !result.IP.Equal(net.IP{10, 0, 0, 50}) {
		t.Errorf("IP = %v, want 10.0.0.50", result.IP)
	}
	if result.Mask.String() != "ffffff00" {
		t.Errorf("Mask = %v, want ffffff00", result.Mask)
	}
	if !result.Gateway.Equal(net.IP{10, 0, 0, 1}) {
		t.Errorf("Gateway = %v, want 10.0.0.1", result.Gateway)
	}
	if len(result.DNS) != 2 {
		t.Fatalf("DNS count = %d, want 2", len(result.DNS))
	}
}
