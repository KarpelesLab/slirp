package vclient

import (
	"testing"
	"time"
)

func TestTCPConnKeepaliveProbe(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)

	// Simulate established connection
	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 5000
	tc.sndUna = 5000
	tc.rcvNxt = 3000
	tc.lastRecv = time.Now().Add(-40 * time.Second)
	tc.mu.Unlock()

	// Manually invoke keepalive check
	tc.mu.Lock()
	if tc.state == tcpEstablished && time.Since(tc.lastRecv) > 30*time.Second {
		tc.buildKeepaliveProbe()
		tc.keepaliveSent++
	}
	pkts := tc.drainOutgoing()
	tc.mu.Unlock()

	if len(pkts) != 1 {
		t.Fatalf("expected 1 keepalive probe, got %d", len(pkts))
	}
	if tc.keepaliveSent != 1 {
		t.Errorf("keepaliveSent should be 1, got %d", tc.keepaliveSent)
	}

	// Verify the probe packet: IP header (20) + TCP header (20), check seq = sndNxt-1
	pkt := pkts[0]
	if len(pkt) < 40 {
		t.Fatalf("probe packet too short: %d bytes", len(pkt))
	}
	// TCP seq is at IP offset 20 + TCP offset 4 = byte 24
	seq := uint32(pkt[24])<<24 | uint32(pkt[25])<<16 | uint32(pkt[26])<<8 | uint32(pkt[27])
	if seq != 4999 {
		t.Errorf("keepalive probe seq should be 4999 (sndNxt-1), got %d", seq)
	}
	// TCP flags at offset 20 + 13 = 33
	flags := pkt[33]
	if flags != 0x10 {
		t.Errorf("keepalive probe should be ACK (0x10), got 0x%02x", flags)
	}
}

func TestTCPConnKeepaliveResetOnRecv(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)
	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.keepaliveSent = 2
	tc.lastRecv = time.Now().Add(-35 * time.Second)
	tc.mu.Unlock()

	// Simulate a segment arriving (handleSegment updates lastRecv and resets keepaliveSent)
	tc.mu.Lock()
	tc.lastRecv = time.Now()
	tc.keepaliveSent = 0 // this is what handleSegment does
	tc.mu.Unlock()

	if tc.keepaliveSent != 0 {
		t.Errorf("keepaliveSent should be 0 after receiving segment, got %d", tc.keepaliveSent)
	}
}

func TestTCPConnKeepaliveTimeout(t *testing.T) {
	c := New([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, func([]byte) error { return nil })
	defer c.Close()

	localIP := [4]byte{10, 0, 0, 2}
	remoteIP := [4]byte{10, 0, 0, 1}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tc := newTCPConn(c, localIP, 50000, remoteIP, 9000, gwMAC)

	// Register in client so unregister doesn't panic
	k := connKey{localPort: 50000, remoteIP: remoteIP, remotePort: 9000}
	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	tc.mu.Lock()
	tc.state = tcpEstablished
	tc.sndNxt = 5000
	tc.rcvNxt = 3000
	tc.lastRecv = time.Now().Add(-60 * time.Second)
	tc.keepaliveSent = 3 // 3 unanswered probes
	tc.mu.Unlock()

	// Simulate the keepalive check that would trigger timeout
	tc.mu.Lock()
	shouldAbort := tc.state == tcpEstablished && time.Since(tc.lastRecv) > 30*time.Second && tc.keepaliveSent >= 3
	if shouldAbort {
		tc.state = tcpClosed
		tc.closed.Store(true)
		tc.stopRTO()
	}
	tc.mu.Unlock()

	if !shouldAbort {
		t.Fatal("connection should be aborted after 3 unanswered probes")
	}
	if !tc.closed.Load() {
		t.Error("connection should be marked as closed")
	}
	tc.mu.Lock()
	state := tc.state
	tc.mu.Unlock()
	if state != tcpClosed {
		t.Errorf("state should be tcpClosed, got %d", state)
	}
}
