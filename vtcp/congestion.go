package vtcp

// CongestionController defines the interface for TCP congestion control algorithms.
type CongestionController interface {
	// OnACK is called when new bytes are acknowledged.
	OnACK(bytesAcked uint32)
	// OnDupACK is called on each duplicate ACK.
	// Returns true if fast retransmit should be triggered (3rd dup ACK).
	OnDupACK() bool
	// OnTimeout is called on RTO timeout (loss detected via timeout).
	OnTimeout()
	// OnFastRetransmit is called when entering fast retransmit/recovery.
	OnFastRetransmit(flightSize uint32)
	// ExitRecovery is called when recovery is complete (all data acked past recovery point).
	ExitRecovery()
	// SendWindow returns the current congestion window in bytes.
	SendWindow() uint32
	// InRecovery reports whether the sender is in fast recovery.
	InRecovery() bool
}

// NewReno implements RFC 5681 TCP congestion control:
// slow start, congestion avoidance, fast retransmit, fast recovery.
type NewReno struct {
	cwnd       uint32 // congestion window (bytes)
	ssthresh   uint32 // slow start threshold (bytes)
	mss        uint32 // max segment size (bytes)
	dupAckCnt  int    // consecutive duplicate ACK count
	recovery   bool   // in fast recovery
	recoverSeq uint32 // SND.NXT at time of fast retransmit entry
}

// NewNewReno creates a NewReno congestion controller.
// Initial cwnd is set to min(10*MSS, max(2*MSS, 4380)) per RFC 6928.
func NewNewReno(mss uint32) *NewReno {
	initialCWND := 10 * mss
	if alt := max(2*mss, 4380); alt < initialCWND {
		initialCWND = alt
	}
	return &NewReno{
		cwnd:     initialCWND,
		ssthresh: ^uint32(0), // infinity until first loss
		mss:      mss,
	}
}

// OnACK processes a new ACK. RFC 5681 Section 3.1.
func (nr *NewReno) OnACK(bytesAcked uint32) {
	nr.dupAckCnt = 0

	if nr.cwnd < nr.ssthresh {
		// Slow start: increase by min(bytesAcked, MSS) per ACK
		inc := bytesAcked
		if inc > nr.mss {
			inc = nr.mss
		}
		nr.cwnd += inc
	} else {
		// Congestion avoidance: increase by MSS^2/cwnd per ACK (approx +1 MSS per RTT)
		inc := nr.mss * nr.mss / nr.cwnd
		if inc == 0 {
			inc = 1
		}
		nr.cwnd += inc
	}
}

// OnDupACK processes a duplicate ACK. Returns true if this is the 3rd dup ACK
// (triggering fast retransmit). RFC 5681 Section 3.2.
func (nr *NewReno) OnDupACK() bool {
	nr.dupAckCnt++
	if nr.dupAckCnt == 3 && !nr.recovery {
		return true
	}
	// During fast recovery, inflate cwnd for each additional dup ACK
	if nr.recovery && nr.dupAckCnt > 3 {
		nr.cwnd += nr.mss
	}
	return false
}

// OnFastRetransmit enters fast recovery. RFC 5681 Section 3.2.
func (nr *NewReno) OnFastRetransmit(flightSize uint32) {
	nr.ssthresh = max(flightSize/2, 2*nr.mss)
	nr.cwnd = nr.ssthresh + 3*nr.mss // inflate for the 3 dup ACKs
	nr.recovery = true
}

// ExitRecovery leaves fast recovery, deflating cwnd. RFC 5681 Section 3.2.
func (nr *NewReno) ExitRecovery() {
	nr.cwnd = nr.ssthresh
	nr.recovery = false
	nr.dupAckCnt = 0
}

// OnTimeout handles RTO timeout. RFC 5681 Section 3.1.
func (nr *NewReno) OnTimeout() {
	nr.ssthresh = max(nr.cwnd/2, 2*nr.mss)
	nr.cwnd = nr.mss // reset to 1 MSS (slow start)
	nr.recovery = false
	nr.dupAckCnt = 0
}

// SendWindow returns the current congestion window.
func (nr *NewReno) SendWindow() uint32 {
	return nr.cwnd
}

// InRecovery reports whether we are in fast recovery.
func (nr *NewReno) InRecovery() bool {
	return nr.recovery
}

// SSThresh returns the current slow start threshold.
func (nr *NewReno) SSThresh() uint32 {
	return nr.ssthresh
}
