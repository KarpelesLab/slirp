package vtcp

import "testing"

func TestSendBufWrite(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	n := sb.Write([]byte("hello"))
	if n != 5 {
		t.Errorf("Write = %d, want 5", n)
	}
	if sb.Pending() != 5 {
		t.Errorf("Pending = %d, want 5", sb.Pending())
	}
	if sb.Unacked() != 0 {
		t.Errorf("Unacked = %d, want 0", sb.Unacked())
	}
}

func TestSendBufFull(t *testing.T) {
	sb := NewSendBuf(5, 1000)
	n := sb.Write([]byte("hello world"))
	if n != 5 {
		t.Errorf("Write = %d, want 5 (capped by capacity)", n)
	}
	n2 := sb.Write([]byte("more"))
	if n2 != 0 {
		t.Errorf("Write when full = %d, want 0", n2)
	}
}

func TestSendBufSendAndAck(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	sb.Write([]byte("hello"))

	// Peek and send
	data := sb.PeekUnsent(10)
	if string(data) != "hello" {
		t.Errorf("PeekUnsent = %q, want %q", data, "hello")
	}
	sb.AdvanceSent(5)
	if sb.Pending() != 0 {
		t.Errorf("Pending after send = %d, want 0", sb.Pending())
	}
	if sb.Unacked() != 5 {
		t.Errorf("Unacked after send = %d, want 5", sb.Unacked())
	}
	if sb.NXT() != 1005 {
		t.Errorf("NXT = %d, want 1005", sb.NXT())
	}

	// ACK
	acked := sb.Acknowledge(1005)
	if acked != 5 {
		t.Errorf("Acknowledge = %d, want 5", acked)
	}
	if sb.Unacked() != 0 {
		t.Errorf("Unacked after ack = %d, want 0", sb.Unacked())
	}
	if sb.UNA() != 1005 {
		t.Errorf("UNA = %d, want 1005", sb.UNA())
	}
	if !sb.IsEmpty() {
		t.Error("buffer should be empty after full ack")
	}
}

func TestSendBufPartialAck(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	sb.Write([]byte("hello world"))
	sb.AdvanceSent(11)

	acked := sb.Acknowledge(1005) // ack first 5 bytes
	if acked != 5 {
		t.Errorf("partial ack = %d, want 5", acked)
	}
	if sb.Unacked() != 6 {
		t.Errorf("Unacked = %d, want 6", sb.Unacked())
	}

	// Retransmit data should be remaining unacked bytes
	retx := sb.RetransmitData(100)
	if string(retx) != " world" {
		t.Errorf("RetransmitData = %q, want %q", retx, " world")
	}
}

func TestSendBufRetransmitCapped(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	sb.Write([]byte("hello world"))
	sb.AdvanceSent(11)

	retx := sb.RetransmitData(3) // only first 3 bytes
	if string(retx) != "hel" {
		t.Errorf("RetransmitData(3) = %q, want %q", retx, "hel")
	}
}

func TestSendBufDuplicateAck(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	sb.Write([]byte("hello"))
	sb.AdvanceSent(5)

	// Duplicate ACK (ack == una) — no change
	acked := sb.Acknowledge(1000)
	if acked != 0 {
		t.Errorf("duplicate ack = %d, want 0", acked)
	}
}

func TestSendBufAckBeyondSent(t *testing.T) {
	sb := NewSendBuf(100, 1000)
	sb.Write([]byte("hello"))
	sb.AdvanceSent(5)

	// ACK beyond what we sent — clamped to nxt
	acked := sb.Acknowledge(2000)
	if acked != 5 {
		t.Errorf("ack beyond sent = %d, want 5", acked)
	}
}

func TestSendBufAvailable(t *testing.T) {
	sb := NewSendBuf(10, 1000)
	sb.Write([]byte("hello"))
	if sb.Available() != 5 {
		t.Errorf("Available = %d, want 5", sb.Available())
	}
}

func TestSendBufSequenceWrap(t *testing.T) {
	// Start near sequence number wraparound
	sb := NewSendBuf(100, 0xFFFFFFF0)
	sb.Write([]byte("wrap"))
	sb.AdvanceSent(4)

	if sb.NXT() != 0xFFFFFFF4 {
		t.Errorf("NXT = %d, want %d", sb.NXT(), uint32(0xFFFFFFF4))
	}

	acked := sb.Acknowledge(0xFFFFFFF4)
	if acked != 4 {
		t.Errorf("ack after wrap = %d, want 4", acked)
	}
}
