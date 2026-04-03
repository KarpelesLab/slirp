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
func testPair(t *testing.T) (client, server *Conn) {
	t.Helper()

	var srvConn *Conn
	var srvMu sync.Mutex

	clientWriter := func(seg []byte) error {
		srvMu.Lock()
		s := srvConn
		srvMu.Unlock()
		if s == nil {
			return nil
		}
		parsed, err := ParseSegment(seg)
		if err != nil {
			return err
		}
		pkts := s.HandleSegment(parsed)
		// Deliver server responses back to client
		for _, pkt := range pkts {
			p, err := ParseSegment(pkt)
			if err != nil {
				continue
			}
			rpkts := client.HandleSegment(p)
			// Deliver client responses back to server (for ACKs etc)
			for _, rpkt := range rpkts {
				rp, err := ParseSegment(rpkt)
				if err != nil {
					continue
				}
				_ = s.HandleSegment(rp)
			}
		}
		return nil
	}

	client = NewConn(ConnConfig{
		LocalPort:  50000,
		RemotePort: 9000,
		Writer:     clientWriter,
		MSS:        1460,
	})

	server = NewConn(ConnConfig{
		LocalPort:  9000,
		RemotePort: 50000,
		Writer: func(seg []byte) error {
			parsed, err := ParseSegment(seg)
			if err != nil {
				return err
			}
			pkts := client.HandleSegment(parsed)
			for _, pkt := range pkts {
				p, err := ParseSegment(pkt)
				if err != nil {
					continue
				}
				srvMu.Lock()
				s := srvConn
				srvMu.Unlock()
				if s != nil {
					_ = s.HandleSegment(p)
				}
			}
			return nil
		},
		MSS: 1460,
	})

	srvMu.Lock()
	srvConn = server
	srvMu.Unlock()

	return client, server
}

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

	// Send RST
	server.HandleSegment(Segment{SrcPort: 50000, DstPort: 9000, Flags: FlagRST})

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
