package vclient

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseMSS(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 80, [6]byte{})

	// Default MSS is 1460
	if tc.mss != 1460 {
		t.Fatalf("default mss = %d, want 1460", tc.mss)
	}

	// MSS option: kind=2, len=4, value=536
	opts := []byte{2, 4, 0x02, 0x18} // 0x0218 = 536
	tc.parseMSS(opts)
	if tc.mss != 536 {
		t.Errorf("mss after parse = %d, want 536", tc.mss)
	}

	// MSS larger than current should not increase
	tc.mss = 536
	opts2 := []byte{2, 4, 0x05, 0xB4} // 0x05B4 = 1460
	tc.parseMSS(opts2)
	if tc.mss != 536 {
		t.Errorf("mss should not increase: got %d, want 536", tc.mss)
	}
}

func TestParseMSSWithNOP(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 80, [6]byte{})

	// NOP (kind=1) before MSS
	opts := []byte{1, 1, 2, 4, 0x02, 0x00} // MSS = 512
	tc.parseMSS(opts)
	if tc.mss != 512 {
		t.Errorf("mss = %d, want 512", tc.mss)
	}
}

func TestParseMSSEndOfOptions(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 80, [6]byte{})

	// End-of-options (kind=0) before MSS
	opts := []byte{0, 2, 4, 0x02, 0x00}
	tc.parseMSS(opts)
	if tc.mss != 1460 {
		t.Errorf("mss should remain default after EOL: got %d, want 1460", tc.mss)
	}
}

func TestParseMSSEmpty(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 80, [6]byte{})

	tc.parseMSS(nil)
	if tc.mss != 1460 {
		t.Errorf("mss should remain default: got %d", tc.mss)
	}
}

// buildIPTCP builds a raw IP+TCP packet suitable for handleSegment.
func buildIPTCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	tcpHdrLen := 20
	ipHdrLen := 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)

	pkt := make([]byte, totalLen)
	// IP header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	// TCP header
	tcp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset = 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window

	if len(payload) > 0 {
		copy(tcp[tcpHdrLen:], payload)
	}
	return pkt
}

func TestHandleSegmentFIN_EstablishedToCloseWait(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// Send FIN+ACK from remote
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1000, 0x11, nil) // FIN+ACK
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpCloseWait {
		t.Errorf("state = %d, want %d (CloseWait)", state, tcpCloseWait)
	}
}

func TestHandleSegmentCloseWait_CloseToLastAck(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpCloseWait
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rcvNxt = 5001
	tc.mu.Unlock()

	// Close from CloseWait should transition to LastAck
	err := tc.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpLastAck {
		t.Errorf("state after Close = %d, want %d (LastAck)", state, tcpLastAck)
	}
}

func TestHandleSegmentLastAck_ACKCloses(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpLastAck
	tc.sndNxt = 1001 // FIN consumed one seq
	tc.sndUna = 1000
	tc.rcvNxt = 5001
	tc.mu.Unlock()

	// ACK for our FIN
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5001, 1001, 0x10, nil) // ACK
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpClosed {
		t.Errorf("state = %d, want %d (Closed)", state, tcpClosed)
	}
	if !tc.closed.Load() {
		t.Error("connection should be marked as closed")
	}
}

func TestHandleSegmentFinWait1_ToFinWait2(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpFinWait1
	tc.sndNxt = 1001 // after our FIN
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// ACK for our FIN (no FIN from them yet)
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1001, 0x10, nil) // ACK
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpFinWait2 {
		t.Errorf("state = %d, want %d (FinWait2)", state, tcpFinWait2)
	}
}

func TestHandleSegmentFinWait2_FINToTimeWait(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpFinWait2
	tc.sndNxt = 1001
	tc.sndUna = 1001
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// FIN+ACK from remote
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1001, 0x11, nil) // FIN+ACK
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpTimeWait {
		t.Errorf("state = %d, want %d (TimeWait)", state, tcpTimeWait)
	}
}

func TestHandleSegmentRST(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// RST from remote
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 0, 0x04, nil) // RST
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpClosed {
		t.Errorf("state = %d, want %d (Closed)", state, tcpClosed)
	}
	if !tc.closed.Load() {
		t.Error("connection should be marked closed after RST")
	}
}

func TestHandleSegmentDataDelivery(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// Data segment
	payload := []byte("hello")
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1000, 0x18, payload) // PSH+ACK
	tc.handleSegment(pkt, 20)

	tc.recvMu.Lock()
	data := make([]byte, len(tc.recvBuf))
	copy(data, tc.recvBuf)
	tc.recvMu.Unlock()

	if string(data) != "hello" {
		t.Errorf("received data = %q, want %q", string(data), "hello")
	}

	tc.mu.Lock()
	if tc.rcvNxt != 5005 {
		t.Errorf("rcvNxt = %d, want 5005", tc.rcvNxt)
	}
	tc.mu.Unlock()
}

func TestOnRTOTimeoutSynSent(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpSynSent
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rto = 100 * time.Millisecond
	tc.mu.Unlock()

	// Trigger RTO
	tc.onRTOTimeout()

	tc.mu.Lock()
	retries := tc.retries
	rto := tc.rto
	pkts := tc.drainOutgoing()
	tc.mu.Unlock()

	if retries != 1 {
		t.Errorf("retries = %d, want 1", retries)
	}
	if rto != 200*time.Millisecond {
		t.Errorf("rto = %v, want 200ms", rto)
	}
	// Should have queued a SYN retransmission (the RTO handler also starts a new timer
	// which queues nothing itself, but the SYN was queued)
	// Note: drainOutgoing was already called by onRTOTimeout, so pkts here should be empty
	// The packets were flushed inside onRTOTimeout
	_ = pkts
}

func TestOnRTOTimeoutMaxRetries(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpSynSent
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.retries = 8 // already at max
	tc.rto = 100 * time.Millisecond
	tc.mu.Unlock()

	tc.onRTOTimeout()

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpClosed {
		t.Errorf("state = %d, want %d (Closed) after max retries", state, tcpClosed)
	}
	if !tc.closed.Load() {
		t.Error("connection should be marked closed after max retries")
	}
}

func TestOnRTOTimeoutEstablished(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 1100
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.sendBuf = []byte("hello world") // 11 bytes unacked
	tc.rto = 100 * time.Millisecond
	tc.rttStart = time.Now() // will be cleared by Karn's algorithm
	tc.mu.Unlock()

	tc.onRTOTimeout()

	tc.mu.Lock()
	retries := tc.retries
	rto := tc.rto
	rttStart := tc.rttStart
	tc.mu.Unlock()

	if retries != 1 {
		t.Errorf("retries = %d, want 1", retries)
	}
	if rto != 200*time.Millisecond {
		t.Errorf("rto = %v, want 200ms (doubled)", rto)
	}
	if !rttStart.IsZero() {
		t.Error("rttStart should be zero after RTO (Karn's algorithm)")
	}
}

func TestOnRTOTimeoutFinWait1(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpFinWait1
	tc.sndNxt = 1001 // after FIN
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.rto = 100 * time.Millisecond
	tc.mu.Unlock()

	tc.onRTOTimeout()

	tc.mu.Lock()
	retries := tc.retries
	// sndNxt should remain 1001 because buildFIN increments and then the code decrements
	sndNxt := tc.sndNxt
	tc.mu.Unlock()

	if retries != 1 {
		t.Errorf("retries = %d, want 1", retries)
	}
	if sndNxt != 1001 {
		t.Errorf("sndNxt = %d, want 1001 (FIN retransmit should not advance)", sndNxt)
	}
}

func TestOnRTOTimeoutAlreadyClosed(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})
	tc.closed.Store(true)
	tc.mu.Lock()
	tc.state = tcpClosed
	tc.mu.Unlock()

	// Should return early without panicking
	tc.onRTOTimeout()

	if tc.retries != 0 {
		t.Errorf("retries should remain 0 for closed conn, got %d", tc.retries)
	}
}

func TestOnRTOTimeoutRTOCap(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpSynSent
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rto = 50 * time.Second // doubling would give 100s, but cap is 60s
	tc.mu.Unlock()

	tc.onRTOTimeout()

	tc.mu.Lock()
	rto := tc.rto
	tc.mu.Unlock()

	if rto != 60*time.Second {
		t.Errorf("rto = %v, want 60s (capped)", rto)
	}
}

func TestHandleSegmentFinWait1_SimultaneousClose(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpFinWait1
	tc.sndNxt = 1001
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// Receive FIN+ACK with ack matching our FIN -> simultaneous close -> TimeWait
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1001, 0x11, nil) // FIN+ACK
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpTimeWait {
		t.Errorf("state = %d, want %d (TimeWait) for simultaneous close", state, tcpTimeWait)
	}
}

func TestHandleSegmentFinWait1_FINWithoutACK(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpFinWait1
	tc.sndNxt = 1001
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	// Receive FIN+ACK but ack does NOT match our sndNxt (doesn't ack our FIN)
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5000, 1000, 0x11, nil) // FIN+ACK, ack=1000 (not 1001)
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpCloseWait {
		t.Errorf("state = %d, want %d (CloseWait)", state, tcpCloseWait)
	}
}

func TestHandleSegmentCloseWait_ACK(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpCloseWait
	tc.sndNxt = 1100
	tc.sndUna = 1000
	tc.rcvNxt = 5001
	tc.sendBuf = make([]byte, 100) // simulate unacked data
	tc.mu.Unlock()

	// ACK in CloseWait state
	pkt := buildIPTCP(remoteIP, localIP, 9000, 50000, 5001, 1050, 0x10, nil) // ACK acking 50 bytes
	tc.handleSegment(pkt, 20)

	tc.mu.Lock()
	sndUna := tc.sndUna
	sendBufLen := len(tc.sendBuf)
	tc.mu.Unlock()

	if sndUna != 1050 {
		t.Errorf("sndUna = %d, want 1050", sndUna)
	}
	if sendBufLen != 50 {
		t.Errorf("sendBuf len = %d, want 50", sendBufLen)
	}
}

func TestCloseFromEstablished(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 1000
	tc.sndUna = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	err := tc.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()

	if state != tcpFinWait1 {
		t.Errorf("state after Close = %d, want %d (FinWait1)", state, tcpFinWait1)
	}
}

func TestCloseAlreadyClosed(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})
	tc.closed.Store(true)

	err := tc.Close()
	if err != nil {
		t.Errorf("Close on already-closed should return nil, got %v", err)
	}
}

func TestCloseFromDefaultState(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})
	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	// state is tcpClosed (default) -- Close should go to default branch
	err := tc.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !tc.closed.Load() {
		t.Error("connection should be marked closed")
	}
}

func TestTCPConnLocalRemoteAddr(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})

	local := tc.LocalAddr().(*net.TCPAddr)
	if local.Port != 50000 {
		t.Errorf("LocalAddr port = %d, want 50000", local.Port)
	}
	remote := tc.RemoteAddr().(*net.TCPAddr)
	if remote.Port != 9000 {
		t.Errorf("RemoteAddr port = %d, want 9000", remote.Port)
	}
}

func TestTCPConnSetWriteDeadline(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})

	if err := tc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestCloseFromCloseWait(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()
	tc := newTCPConn(c, [4]byte{10, 0, 0, 2}, 50000, [4]byte{10, 0, 0, 1}, 9000, [6]byte{})

	k := connKey{localPort: 50000, remoteIP: [4]byte{10, 0, 0, 1}, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpCloseWait
	tc.sndNxt = 1000
	tc.rcvNxt = 5000
	tc.mu.Unlock()

	err := tc.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()
	if state != tcpLastAck {
		t.Errorf("state = %d, want tcpLastAck (%d)", state, tcpLastAck)
	}
}
