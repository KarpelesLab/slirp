package slirp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// createTCPPacket6 builds a raw IPv6+TCP packet (no Ethernet header).
func createTCPPacket6(srcIP, dstIP [16]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	thl := 20
	payloadLen := thl + len(payload)

	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = 6  // Next Header: TCP
	ip[7] = 64 // Hop Limit
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	tcp := make([]byte, thl)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (5 << 4) // Data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // Window

	var tcpWithPayload []byte
	if len(payload) > 0 {
		tcpWithPayload = make([]byte, len(tcp)+len(payload))
		copy(tcpWithPayload, tcp)
		copy(tcpWithPayload[len(tcp):], payload)
	} else {
		tcpWithPayload = tcp
	}
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], IPv6Checksum(srcIP, dstIP, 6, uint32(len(tcpWithPayload)), tcpWithPayload))

	pkt := make([]byte, len(ip)+len(tcp)+len(payload))
	copy(pkt, ip)
	copy(pkt[len(ip):], tcp)
	copy(pkt[len(ip)+len(tcp):], payload)
	return pkt
}

func TestNewTCPConn6(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 2
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn6(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	if conn == nil {
		t.Fatal("newTCPConn6 returned nil")
	}
	if conn.cSrcIP != srcIP {
		t.Error("source IP not set correctly")
	}
	if conn.cSrcPort != 12345 {
		t.Error("source port not set correctly")
	}
	if conn.rIP != dstIP {
		t.Error("remote IP not set correctly")
	}
	if conn.rPort != 80 {
		t.Error("remote port not set correctly")
	}
	if conn.mss != 1440 {
		t.Errorf("default MSS should be 1440 for IPv6, got %d", conn.mss)
	}
}

func TestBuildTCPPacket6(t *testing.T) {
	srcMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	dstMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 2
	payload := []byte("test data")

	pkt := BuildTCPPacket6(srcMAC, dstMAC, srcIP, dstIP, 12345, 80, 1000, 2000, 0x18, payload)

	// Check Ethernet header
	if len(pkt) < 14+40+20 {
		t.Fatal("packet too short")
	}
	if !bytesEqual(pkt[0:6], dstMAC[:]) {
		t.Error("destination MAC incorrect")
	}
	if !bytesEqual(pkt[6:12], srcMAC[:]) {
		t.Error("source MAC incorrect")
	}
	if binary.BigEndian.Uint16(pkt[12:14]) != 0x86DD {
		t.Error("EtherType should be 0x86DD (IPv6)")
	}

	// Check IPv6 header
	ipStart := 14
	if pkt[ipStart]>>4 != 6 {
		t.Error("IP version should be 6")
	}
	if pkt[ipStart+6] != 6 {
		t.Error("Next Header should be 6 (TCP)")
	}

	// Check TCP header
	tcpStart := ipStart + 40
	if binary.BigEndian.Uint16(pkt[tcpStart:tcpStart+2]) != 12345 {
		t.Error("TCP source port incorrect")
	}
	if binary.BigEndian.Uint16(pkt[tcpStart+2:tcpStart+4]) != 80 {
		t.Error("TCP dest port incorrect")
	}
	if binary.BigEndian.Uint32(pkt[tcpStart+4:tcpStart+8]) != 1000 {
		t.Error("TCP seq incorrect")
	}
	if binary.BigEndian.Uint32(pkt[tcpStart+8:tcpStart+12]) != 2000 {
		t.Error("TCP ack incorrect")
	}
	if pkt[tcpStart+13] != 0x18 {
		t.Errorf("TCP flags should be 0x18, got 0x%02x", pkt[tcpStart+13])
	}

	// Check payload
	payloadStart := tcpStart + 20
	if !bytesEqual(pkt[payloadStart:], payload) {
		t.Error("payload not copied correctly")
	}
}

func TestTCPConn6HandleSYN(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			c.Close()
		}
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 1 // ::1
	dstIP[15] = 1 // ::1
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var receivedFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		receivedFrames = append(receivedFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn6(srcIP, 54321, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	synPacket := createTCPPacket6(srcIP, dstIP, 54321, uint16(serverAddr.Port), 1000, 0, 0x02, nil)
	err = conn.handleOutbound(synPacket)
	if err != nil {
		t.Fatalf("handleOutbound SYN failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 1 {
		t.Error("expected at least one frame (SYN-ACK), got none")
	}

	if conn.conn == nil {
		t.Error("TCP6 connection should be established")
	}
	if conn.cSeq != 1001 {
		t.Errorf("client seq should be 1001, got %d", conn.cSeq)
	}
}

func TestTCPConn6HandleRST(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			buf := make([]byte, 1024)
			for {
				if _, err := c.Read(buf); err != nil {
					break
				}
			}
			c.Close()
		}
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn6(srcIP, 54330, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket6(srcIP, dstIP, 54330, uint16(serverAddr.Port), 1000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	// RST
	rstPacket := createTCPPacket6(srcIP, dstIP, 54330, uint16(serverAddr.Port), 1001, conn.sSeq+1, 0x04, nil)
	err = conn.handleOutbound(rstPacket)
	if err != nil {
		t.Fatalf("RST handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()

	if !closed {
		t.Error("connection should be closed after RST")
	}
}

func TestTCPConn6ACKHandshakeAndData(t *testing.T) {
	// Echo server
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					break
				}
				c.Write(buf[:n])
			}
			c.Close()
		}
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var receivedFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		receivedFrames = append(receivedFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn6(srcIP, 54331, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket6(srcIP, dstIP, 54331, uint16(serverAddr.Port), 2000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// ACK to complete handshake
	ackPacket := createTCPPacket6(srcIP, dstIP, 54331, uint16(serverAddr.Port), 2001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	established := conn.established
	conn.mu.Unlock()

	if !established {
		t.Error("connection should be established after ACK")
	}

	// Send data
	payload := []byte("IPv6 data!")
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	dataPacket := createTCPPacket6(srcIP, dstIP, 54331, uint16(serverAddr.Port), 2001, sSeqNow, 0x18, payload)
	err = conn.handleOutbound(dataPacket)
	if err != nil {
		t.Fatalf("data handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	cSeq := conn.cSeq
	conn.mu.Unlock()

	if cSeq != 2001+uint32(len(payload)) {
		t.Errorf("cSeq should be %d, got %d", 2001+uint32(len(payload)), cSeq)
	}

	// Wait for readFromRemote to receive echo data
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	frameCount := len(receivedFrames)
	mu.Unlock()

	if frameCount < 2 {
		t.Errorf("expected at least 2 frames (SYN-ACK + ACK), got %d", frameCount)
	}
}

func TestTCPConn6FINHandling(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var receivedFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		receivedFrames = append(receivedFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn6(srcIP, 54332, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket6(srcIP, dstIP, 54332, uint16(serverAddr.Port), 3000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// Complete handshake
	ackPacket := createTCPPacket6(srcIP, dstIP, 54332, uint16(serverAddr.Port), 3001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send FIN
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	finPacket := createTCPPacket6(srcIP, dstIP, 54332, uint16(serverAddr.Port), 3001, sSeqNow, 0x01, nil)
	err = conn.handleOutbound(finPacket)
	if err != nil {
		t.Fatalf("FIN handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	cSeq := conn.cSeq
	conn.mu.Unlock()

	// Half-close: connection stays open for server responses
	if closed {
		t.Error("connection should NOT be fully closed after client FIN (half-close)")
	}
	if cSeq != 3002 {
		t.Errorf("cSeq should be 3002 after FIN, got %d", cSeq)
	}

	// Check for ACK (not FIN-ACK) response to client's FIN
	mu.Lock()
	found := false
	for _, frame := range receivedFrames {
		if len(frame) >= 14+40+20 {
			tcpHdr := frame[14+40:]
			flags := tcpHdr[13]
			if flags == 0x10 { // ACK only (half-close response)
				found = true
				break
			}
		}
	}
	mu.Unlock()

	if !found {
		t.Error("expected an ACK packet to be sent for client FIN (half-close)")
	}
}

func TestTCPConn6FlushSendQ(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 2
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var sentFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		sentFrames = append(sentFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn6(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	conn.recvWnd = 8192
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.sendQ = []byte("Hello from IPv6 test data.")

	conn.mu.Lock()
	conn.flushSendQ()
	pkts := conn.drainOutgoing()
	conn.mu.Unlock()

	if len(conn.sendQ) != 0 {
		t.Errorf("sendQ should be empty after flush, has %d bytes", len(conn.sendQ))
	}

	if len(pkts) < 1 {
		t.Error("expected at least one packet to be queued")
	}
}

func TestTCPConn6MaintenanceKeepalive(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 2
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	var sentFrames [][]byte
	var mu sync.Mutex
	writer := func(b []byte) error {
		mu.Lock()
		frame := make([]byte, len(b))
		copy(frame, b)
		sentFrames = append(sentFrames, frame)
		mu.Unlock()
		return nil
	}

	conn := newTCPConn6(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)
	conn.established = true
	conn.sSeq = 5000
	conn.cSeq = 3000
	conn.lastAct = time.Now().Add(-40 * time.Second)

	// Simulate maintenance tick - keepalive probe
	conn.mu.Lock()
	if conn.established && time.Since(conn.lastAct) > 30*time.Second {
		pkt := BuildTCPPacket6(conn.gwMAC, conn.clientMAC, conn.rIP, conn.cSrcIP, conn.rPort, conn.cSrcPort, conn.sSeq-1, conn.cSeq, 0x10, nil)
		_ = conn.w(pkt)
		conn.keepaliveSent++
	}
	conn.mu.Unlock()

	mu.Lock()
	frameCount := len(sentFrames)
	mu.Unlock()

	if frameCount != 1 {
		t.Fatalf("expected 1 keepalive probe, got %d", frameCount)
	}

	// Verify it's an ACK with seq-1
	frame := sentFrames[0]
	tcpStart := 14 + 40 // Ethernet + IPv6
	seq := binary.BigEndian.Uint32(frame[tcpStart+4 : tcpStart+8])
	if seq != 4999 {
		t.Errorf("keepalive probe should have seq=4999, got %d", seq)
	}
	if conn.keepaliveSent != 1 {
		t.Errorf("keepaliveSent should be 1, got %d", conn.keepaliveSent)
	}
}

func TestTCPConn6DataFINPiggyback(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on IPv6 localhost: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	var serverReceived []byte
	var srvMu sync.Mutex
	go func() {
		c, err := listener.Accept()
		if err == nil {
			buf := make([]byte, 1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					break
				}
				srvMu.Lock()
				serverReceived = append(serverReceived, buf[:n]...)
				srvMu.Unlock()
			}
			c.Close()
		}
	}()

	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 1
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn6(srcIP, 54333, dstIP, uint16(serverAddr.Port), clientMAC, gwMAC, writer)

	// SYN
	synPacket := createTCPPacket6(srcIP, dstIP, 54333, uint16(serverAddr.Port), 4000, 0, 0x02, nil)
	_ = conn.handleOutbound(synPacket)
	time.Sleep(50 * time.Millisecond)

	conn.mu.Lock()
	sSeq := conn.sSeq
	conn.mu.Unlock()

	// Complete handshake
	ackPacket := createTCPPacket6(srcIP, dstIP, 54333, uint16(serverAddr.Port), 4001, sSeq+1, 0x10, nil)
	_ = conn.handleOutbound(ackPacket)
	time.Sleep(50 * time.Millisecond)

	// Send data+FIN (PSH+ACK+FIN = 0x19)
	payload := []byte("last ipv6")
	conn.mu.Lock()
	sSeqNow := conn.sSeq
	conn.mu.Unlock()

	dataFinPacket := createTCPPacket6(srcIP, dstIP, 54333, uint16(serverAddr.Port), 4001, sSeqNow, 0x19, payload)
	err = conn.handleOutbound(dataFinPacket)
	if err != nil {
		t.Fatalf("data+FIN handleOutbound failed: %v", err)
	}

	conn.mu.Lock()
	closed := conn.closed
	cSeq := conn.cSeq
	conn.mu.Unlock()

	// Half-close: connection stays open for server responses
	if closed {
		t.Error("connection should NOT be fully closed after data+FIN (half-close)")
	}
	expectedCSeq := uint32(4001 + len(payload) + 1)
	if cSeq != expectedCSeq {
		t.Errorf("cSeq should be %d after data+FIN, got %d", expectedCSeq, cSeq)
	}

	// Verify server received data
	time.Sleep(100 * time.Millisecond)
	srvMu.Lock()
	got := string(serverReceived)
	srvMu.Unlock()
	if got != "last ipv6" {
		t.Errorf("server should have received %q, got %q", "last ipv6", got)
	}
}

func TestTCPConn6ShortPackets(t *testing.T) {
	var srcIP, dstIP [16]byte
	srcIP[15] = 1
	dstIP[15] = 2
	clientMAC := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	gwMAC := [6]byte{0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	writer := func(b []byte) error { return nil }

	conn := newTCPConn6(srcIP, 12345, dstIP, 80, clientMAC, gwMAC, writer)

	// Too short for IPv6 header
	err := conn.handleOutbound(make([]byte, 30))
	if err != nil {
		t.Errorf("should handle short packet gracefully, got: %v", err)
	}

	// IPv6 header present but TCP header too short
	shortTcp := make([]byte, 50)
	shortTcp[0] = 0x60
	binary.BigEndian.PutUint16(shortTcp[4:6], 10) // only 10 byte payload
	shortTcp[6] = 6
	err = conn.handleOutbound(shortTcp)
	if err != nil {
		t.Errorf("should handle short TCP gracefully, got: %v", err)
	}
}
