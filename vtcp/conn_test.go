package vtcp

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// testPair creates two connected Conns (client + server) for testing.
// Packets from one are delivered to the other synchronously.

func TestConnPassiveOpen(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	// Simulate SYN arrival
	syn := Segment{
		SrcPort: 50000,
		DstPort: 9000,
		Seq:     1000,
		Flags:   FlagSYN,
		Window:  65535,
		Options: []Option{MSSOption(1460)},
	}
	pkts := server.AcceptSYN(syn)
	if len(pkts) == 0 {
		t.Fatal("AcceptSYN should produce a SYN-ACK")
	}
	if server.State() != StateSynReceived {
		t.Errorf("state = %v, want SYN-RECEIVED", server.State())
	}

	// Parse SYN-ACK
	synack, err := ParseSegment(pkts[0])
	if err != nil {
		t.Fatalf("parse SYN-ACK: %v", err)
	}
	if !synack.HasFlag(FlagSYN) || !synack.HasFlag(FlagACK) {
		t.Errorf("flags = 0x%02x, want SYN+ACK", synack.Flags)
	}
	if synack.Ack != 1001 {
		t.Errorf("SYN-ACK ack = %d, want 1001", synack.Ack)
	}

	// Send ACK to complete handshake
	ack := Segment{
		SrcPort: 50000,
		DstPort: 9000,
		Seq:     1001,
		Ack:     synack.Seq + 1,
		Flags:   FlagACK,
		Window:  65535,
	}
	server.HandleSegment(ack)
	if server.State() != StateEstablished {
		t.Errorf("state = %v, want ESTABLISHED", server.State())
	}
}

func TestConnActiveOpen(t *testing.T) {
	var sent []Segment
	var mu sync.Mutex

	conn := NewConn(ConnConfig{
		LocalPort:  50000,
		RemotePort: 9000,
		Writer: func(seg []byte) error {
			parsed, _ := ParseSegment(seg)
			mu.Lock()
			sent = append(sent, parsed)
			mu.Unlock()
			return nil
		},
		MSS: 1460,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start connect in background
	done := make(chan error, 1)
	go func() { done <- conn.Connect(ctx) }()

	// Wait for SYN
	time.Sleep(10 * time.Millisecond)
	mu.Lock()
	if len(sent) == 0 {
		mu.Unlock()
		t.Fatal("no SYN sent")
	}
	syn := sent[0]
	mu.Unlock()

	if !syn.HasFlag(FlagSYN) {
		t.Fatalf("first packet should be SYN, got flags=0x%02x", syn.Flags)
	}

	// Respond with SYN-ACK
	synack := Segment{
		SrcPort: 9000,
		DstPort: 50000,
		Seq:     2000,
		Ack:     syn.Seq + 1,
		Flags:   FlagSYN | FlagACK,
		Window:  65535,
		Options: []Option{MSSOption(1460)},
	}
	conn.HandleSegment(synack)

	// Should complete
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect timed out")
	}

	if conn.State() != StateEstablished {
		t.Errorf("state = %v, want ESTABLISHED", conn.State())
	}
}

func TestConnDataTransfer(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])

	// Complete handshake
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Send data
	server.HandleSegment(Segment{
		SrcPort: 50000, DstPort: 9000,
		Seq: 1001, Ack: synack.Seq + 1,
		Flags: FlagACK | FlagPSH, Window: 65535,
		Payload: []byte("hello"),
	})

	// Read from server
	buf := make([]byte, 100)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", buf[:n], "hello")
	}
}

func TestConnWriteAndACK(t *testing.T) {
	var sent [][]byte
	var mu sync.Mutex

	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer: func(seg []byte) error {
			cp := make([]byte, len(seg))
			copy(cp, seg)
			mu.Lock()
			sent = append(sent, cp)
			mu.Unlock()
			return nil
		},
		MSS: 1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	mu.Lock()
	sent = nil // clear handshake packets
	mu.Unlock()

	// Write data
	n, err := server.Write([]byte("world"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("Write = %d, want 5", n)
	}

	// Should have queued a data segment
	mu.Lock()
	pktCount := len(sent)
	mu.Unlock()
	if pktCount == 0 {
		t.Fatal("no data segment sent after Write")
	}

	// Parse the data segment
	dataSeg, err := ParseSegment(sent[0])
	if err != nil {
		t.Fatalf("parse data seg: %v", err)
	}
	if string(dataSeg.Payload) != "world" {
		t.Errorf("data payload = %q, want %q", dataSeg.Payload, "world")
	}
}

func TestConnRST(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Send RST with correct SEQ (must == RCV.NXT per RFC 5961)
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Flags: FlagRST})

	if server.State() != StateClosed {
		t.Errorf("state = %v, want CLOSED", server.State())
	}
}

func TestConnFINFromRemote(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Remote sends FIN
	server.HandleSegment(Segment{
		SrcPort: 50000, DstPort: 9000,
		Seq: 1001, Ack: synack.Seq + 1,
		Flags: FlagFIN | FlagACK, Window: 65535,
	})

	if server.State() != StateCloseWait {
		t.Errorf("state = %v, want CLOSE-WAIT", server.State())
	}

	// Read should return EOF
	buf := make([]byte, 100)
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := server.Read(buf)
	if err != io.EOF {
		t.Errorf("Read err = %v, want io.EOF", err)
	}
}

func TestConnClose(t *testing.T) {
	var sent [][]byte
	var mu sync.Mutex

	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer: func(seg []byte) error {
			cp := make([]byte, len(seg))
			copy(cp, seg)
			mu.Lock()
			sent = append(sent, cp)
			mu.Unlock()
			return nil
		},
		MSS: 1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	mu.Lock()
	sent = nil
	mu.Unlock()

	// Close the server side
	err := server.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	if server.State() != StateFinWait1 {
		t.Errorf("state = %v, want FIN-WAIT-1", server.State())
	}

	// Should have sent FIN
	mu.Lock()
	if len(sent) == 0 {
		mu.Unlock()
		t.Fatal("no FIN sent")
	}
	fin, _ := ParseSegment(sent[0])
	mu.Unlock()
	if !fin.HasFlag(FlagFIN) {
		t.Errorf("expected FIN flag, got 0x%02x", fin.Flags)
	}
}

func TestConnAbort(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	rstPkts := server.Abort()
	if len(rstPkts) == 0 {
		t.Fatal("Abort should send RST")
	}
	rst, _ := ParseSegment(rstPkts[0])
	if !rst.HasFlag(FlagRST) {
		t.Errorf("Abort should send RST, got flags=0x%02x", rst.Flags)
	}
	if server.State() != StateClosed {
		t.Errorf("state = %v, want CLOSED", server.State())
	}
}

func TestConnReadDeadline(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
		MSS:        1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 100)
	_, err := server.Read(buf)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestConnDoubleClose(t *testing.T) {
	c := NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer:     func(seg []byte) error { return nil },
	})
	// Close on a never-connected conn should not panic
	c.Close()
	c.Close()
}

func TestConnStateString(t *testing.T) {
	if StateClosed.String() != "CLOSED" {
		t.Errorf("StateClosed = %q", StateClosed.String())
	}
	if StateEstablished.String() != "ESTABLISHED" {
		t.Errorf("StateEstablished = %q", StateEstablished.String())
	}
}

// --- RFC 9293 Compliance Tests ---

// TestRFC9293_SequenceValidation tests that out-of-window segments are rejected with ACK.
func TestRFC9293_SequenceValidation(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
		MSS:    1460, RecvBufSize: 4096,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Send segment with seq far beyond even the max recv buffer
	respPkts := server.HandleSegment(Segment{
		SrcPort: 50000, DstPort: 9000,
		Seq: 1001 + 2000000, // way beyond 1MB window
		Ack: synack.Seq + 1, Flags: FlagACK | FlagPSH,
		Window: 65535, Payload: []byte("out of window"),
	})

	if len(respPkts) == 0 {
		t.Fatal("expected ACK response to out-of-window segment")
	}
	resp, _ := ParseSegment(respPkts[0])
	if !resp.HasFlag(FlagACK) {
		t.Errorf("response should be ACK, got flags=0x%02x", resp.Flags)
	}
}

// TestRFC9293_RSTValidation tests that RST with wrong seq is rejected (RFC 5961).
func TestRFC9293_RSTValidation(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
		MSS:    1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// RST with wrong seq (not RCV.NXT) — should be ignored
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 9999, Flags: FlagRST})
	if server.State() != StateEstablished {
		t.Errorf("RST with wrong seq should be ignored, state = %v", server.State())
	}

	// RST with correct seq (== RCV.NXT) — should close
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Flags: FlagRST})
	if server.State() != StateClosed {
		t.Errorf("RST with correct seq should close, state = %v", server.State())
	}
}

// TestRFC9293_SYNInEstablished tests that SYN in ESTABLISHED triggers challenge ACK.
func TestRFC9293_SYNInEstablished(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
		MSS:    1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// SYN in ESTABLISHED — should get challenge ACK (RFC 5961 §4)
	respPkts := server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Flags: FlagSYN | FlagACK, Ack: synack.Seq + 1, Window: 65535})

	if server.State() != StateEstablished {
		t.Errorf("SYN in ESTABLISHED should NOT close, state = %v", server.State())
	}
	if len(respPkts) == 0 {
		t.Fatal("expected challenge ACK for SYN in ESTABLISHED")
	}
	resp, _ := ParseSegment(respPkts[0])
	if !resp.HasFlag(FlagACK) {
		t.Errorf("response should be ACK, got flags=0x%02x", resp.Flags)
	}
}

// TestRFC9293_ACKRequired tests that segments without ACK are dropped.
func TestRFC9293_ACKRequired(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
		MSS:    1460,
	})

	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1001, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Data segment WITHOUT ACK flag — should be dropped
	server.HandleSegment(Segment{
		SrcPort: 50000, DstPort: 9000,
		Seq: 1001, Flags: FlagPSH, // no ACK!
		Window: 65535, Payload: []byte("no ack"),
	})

	// Data should not have been delivered
	buf := make([]byte, 100)
	server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := server.Read(buf)
	if err == nil {
		t.Error("expected timeout — segment without ACK should be dropped")
	}
}

// TestRFC9293_RSTForClosed tests RST generation for segments to CLOSED conn.
func TestRFC9293_RSTForClosed(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
	})

	// Segment with ACK → RST with SEQ=SEG.ACK
	respPkts := server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 100, Ack: 200, Flags: FlagACK})
	if len(respPkts) == 0 {
		t.Fatal("expected RST for segment to CLOSED")
	}
	rst, _ := ParseSegment(respPkts[0])
	if !rst.HasFlag(FlagRST) {
		t.Fatalf("expected RST, got flags=0x%02x", rst.Flags)
	}
	if rst.Seq != 200 {
		t.Errorf("RST seq = %d, want 200 (SEG.ACK)", rst.Seq)
	}

	// Segment without ACK → RST+ACK with SEQ=0
	respPkts = server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 100, Flags: FlagSYN})
	if len(respPkts) == 0 {
		t.Fatal("expected RST for SYN to CLOSED")
	}
	rst, _ = ParseSegment(respPkts[0])
	if !rst.HasFlag(FlagRST) {
		t.Fatalf("expected RST, got flags=0x%02x", rst.Flags)
	}
	if rst.Seq != 0 {
		t.Errorf("RST seq = %d, want 0", rst.Seq)
	}
	if !rst.HasFlag(FlagACK) {
		t.Error("RST should have ACK flag")
	}
}

// TestRFC9293_SimultaneousOpen tests that bare SYN in SYN-SENT is handled.
func TestRFC9293_SimultaneousOpen(t *testing.T) {
	var sentA, sentB []Segment

	connA := NewConn(ConnConfig{
		LocalPort: 50000, RemotePort: 60000,
		Writer: func(seg []byte) error {
			p, _ := ParseSegment(seg)
			sentA = append(sentA, p)
			return nil
		},
		MSS: 1460,
	})
	connB := NewConn(ConnConfig{
		LocalPort: 60000, RemotePort: 50000,
		Writer: func(seg []byte) error {
			p, _ := ParseSegment(seg)
			sentB = append(sentB, p)
			return nil
		},
		MSS: 1460,
	})

	// Both sides send SYN (via Connect-like setup)
	// Manually set both sides to SYN-SENT with their ISNs
	connA.mu.Lock()
	issA := randUint32()
	connA.sendBuf = NewSendBuf(DefaultSendBuf, issA)
	connA.recvBuf = NewRecvBuf(0, DefaultRecvBuf)
	connA.state = StateSynSent
	connA.sendBuf.AdvanceSent(1) // SYN consumed
	connA.mu.Unlock()

	connB.mu.Lock()
	issB := randUint32()
	connB.sendBuf = NewSendBuf(DefaultSendBuf, issB)
	connB.recvBuf = NewRecvBuf(0, DefaultRecvBuf)
	connB.state = StateSynSent
	connB.sendBuf.AdvanceSent(1) // SYN consumed
	connB.mu.Unlock()

	// Build the SYN segments (not queued in outgoing, just for exchange)
	synA := Segment{SrcPort: 50000, DstPort: 60000, Seq: issA, Flags: FlagSYN, Window: 65535}
	synB := Segment{SrcPort: 60000, DstPort: 50000, Seq: issB, Flags: FlagSYN, Window: 65535}

	// A receives B's SYN (simultaneous open)
	respA := connA.HandleSegment(synB)
	if connA.State() != StateSynReceived {
		t.Errorf("A should be SYN-RECEIVED after bare SYN, got %v", connA.State())
	}
	if len(respA) == 0 {
		t.Fatal("A should send SYN-ACK")
	}
	synackA, _ := ParseSegment(respA[0])
	if !synackA.HasFlag(FlagSYN) || !synackA.HasFlag(FlagACK) {
		t.Errorf("A's response should be SYN-ACK, got 0x%02x", synackA.Flags)
	}

	// B receives A's SYN (simultaneous open)
	respB := connB.HandleSegment(synA)
	if connB.State() != StateSynReceived {
		t.Errorf("B should be SYN-RECEIVED after bare SYN, got %v", connB.State())
	}
	synackB, _ := ParseSegment(respB[0])

	// A receives B's SYN-ACK → ESTABLISHED
	connA.HandleSegment(synackB)
	if connA.State() != StateEstablished {
		t.Errorf("A should be ESTABLISHED after SYN-ACK, got %v", connA.State())
	}

	// B receives A's SYN-ACK → ESTABLISHED
	connB.HandleSegment(synackA)
	if connB.State() != StateEstablished {
		t.Errorf("B should be ESTABLISHED after SYN-ACK, got %v", connB.State())
	}
}

// TestRFC9293_DataInSYN tests that payload in SYN is buffered.
func TestRFC9293_DataInSYN(t *testing.T) {
	server := NewConn(ConnConfig{
		LocalPort: 9000, RemotePort: 50000,
		Writer: func(seg []byte) error { return nil },
		MSS:    1460,
	})

	// SYN with payload data
	syn := Segment{SrcPort: 50000, DstPort: 9000, Seq: 1000, Flags: FlagSYN, Window: 65535, Payload: []byte("early")}
	pkts := server.AcceptSYN(syn)
	synack, _ := ParseSegment(pkts[0])

	// Complete handshake
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Seq: 1006, Ack: synack.Seq + 1, Flags: FlagACK, Window: 65535})

	// Data from SYN should be readable
	buf := make([]byte, 100)
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "early" {
		t.Errorf("Read = %q, want %q", buf[:n], "early")
	}
}
