package vtcp

// SendBuf tracks application data through the TCP send pipeline:
//
//	[acknowledged] [sent but unacked] [unsent / queued] [free space]
//	               ^                  ^                 ^
//	               una                nxt               tail
//
// The buffer is a simple slice-based implementation. Data is appended
// at the tail and removed from the front as it is acknowledged.
type SendBuf struct {
	buf []byte // all unacknowledged + unsent data
	cap int    // max buffer capacity

	una uint32 // SND.UNA: first unacked sequence
	nxt uint32 // SND.NXT: next sequence to send

	// buf[0] corresponds to sequence 'una'.
	// buf[0 .. nxt-una) is sent but unacked.
	// buf[nxt-una .. len(buf)) is unsent.
}

// NewSendBuf creates a send buffer with the given capacity and initial sequence number.
func NewSendBuf(capacity int, initialSeq uint32) *SendBuf {
	return &SendBuf{
		cap: capacity,
		una: initialSeq,
		nxt: initialSeq,
	}
}

// Write appends application data. Returns the number of bytes accepted.
// May return less than len(p) if the buffer is full.
func (s *SendBuf) Write(p []byte) int {
	avail := s.cap - len(s.buf)
	if avail <= 0 {
		return 0
	}
	n := len(p)
	if n > avail {
		n = avail
	}
	s.buf = append(s.buf, p[:n]...)
	return n
}

// Pending returns the number of bytes queued but not yet sent.
func (s *SendBuf) Pending() int {
	sent := int(s.nxt - s.una)
	return len(s.buf) - sent
}

// Unacked returns the number of sent-but-unacknowledged bytes.
func (s *SendBuf) Unacked() int {
	return int(s.nxt - s.una)
}

// PeekUnsent returns up to n bytes of unsent data without consuming them.
func (s *SendBuf) PeekUnsent(n int) []byte {
	offset := int(s.nxt - s.una)
	unsent := s.buf[offset:]
	if len(unsent) > n {
		unsent = unsent[:n]
	}
	return unsent
}

// AdvanceSent marks n bytes as sent (moves nxt forward).
func (s *SendBuf) AdvanceSent(n int) {
	s.nxt += uint32(n)
}

// Acknowledge advances una to ack, freeing buffer space.
// Returns the number of bytes newly acknowledged.
func (s *SendBuf) Acknowledge(ack uint32) uint32 {
	if !SeqAfter(ack, s.una) {
		return 0
	}
	if SeqAfter(ack, s.nxt) {
		// ACK beyond what we sent — clamp to nxt
		ack = s.nxt
	}
	n := ack - s.una
	if int(n) > len(s.buf) {
		n = uint32(len(s.buf))
	}
	s.buf = s.buf[n:]
	s.una = ack
	return n
}

// RetransmitData returns the first n bytes of unacknowledged data (from una).
func (s *SendBuf) RetransmitData(n int) []byte {
	unacked := int(s.nxt - s.una)
	if unacked > len(s.buf) {
		unacked = len(s.buf)
	}
	data := s.buf[:unacked]
	if len(data) > n {
		data = data[:n]
	}
	return data
}

// IsEmpty reports whether all data is acknowledged and nothing is queued.
func (s *SendBuf) IsEmpty() bool {
	return len(s.buf) == 0
}

// UNA returns SND.UNA.
func (s *SendBuf) UNA() uint32 { return s.una }

// NXT returns SND.NXT.
func (s *SendBuf) NXT() uint32 { return s.nxt }

// Available returns the number of bytes of free space in the buffer.
func (s *SendBuf) Available() int {
	return s.cap - len(s.buf)
}
