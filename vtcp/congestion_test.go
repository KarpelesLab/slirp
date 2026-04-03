package vtcp

import "testing"

func TestNewRenoInitialWindow(t *testing.T) {
	nr := NewNewReno(1460)
	// RFC 6928: initial cwnd = min(10*MSS, max(2*MSS, 4380))
	// 10*1460 = 14600, max(2*1460, 4380) = max(2920, 4380) = 4380
	// min(14600, 4380) = 4380
	if nr.SendWindow() != 4380 {
		t.Errorf("initial cwnd = %d, want 4380", nr.SendWindow())
	}
}

func TestNewRenoSlowStart(t *testing.T) {
	nr := NewNewReno(1000)
	initial := nr.SendWindow()

	// ACK for 1000 bytes in slow start → cwnd += MSS
	nr.OnACK(1000)
	if nr.SendWindow() != initial+1000 {
		t.Errorf("after ACK: cwnd = %d, want %d", nr.SendWindow(), initial+1000)
	}
}

func TestNewRenoCongestionAvoidance(t *testing.T) {
	nr := NewNewReno(1000)
	nr.ssthresh = 3000
	nr.cwnd = 4000 // above ssthresh → congestion avoidance

	before := nr.SendWindow()
	nr.OnACK(1000)
	after := nr.SendWindow()

	// Should increase by MSS^2/cwnd = 1000000/4000 = 250
	expected := before + 250
	if after != expected {
		t.Errorf("congestion avoidance: cwnd = %d, want %d", after, expected)
	}
}

func TestNewRenoFastRetransmit(t *testing.T) {
	nr := NewNewReno(1000)
	nr.cwnd = 10000
	nr.ssthresh = 20000

	// 3 duplicate ACKs trigger fast retransmit
	nr.OnDupACK()
	nr.OnDupACK()
	trigger := nr.OnDupACK()
	if !trigger {
		t.Error("3rd dup ACK should trigger fast retransmit")
	}

	// Enter fast recovery
	nr.OnFastRetransmit(8000) // flight size = 8000
	// ssthresh = max(8000/2, 2*1000) = max(4000, 2000) = 4000
	if nr.SSThresh() != 4000 {
		t.Errorf("ssthresh = %d, want 4000", nr.SSThresh())
	}
	// cwnd = ssthresh + 3*MSS = 4000 + 3000 = 7000
	if nr.SendWindow() != 7000 {
		t.Errorf("cwnd after fast retransmit = %d, want 7000", nr.SendWindow())
	}
	if !nr.InRecovery() {
		t.Error("should be in recovery")
	}
}

func TestNewRenoRecoveryInflation(t *testing.T) {
	nr := NewNewReno(1000)
	nr.cwnd = 10000
	nr.OnDupACK()
	nr.OnDupACK()
	nr.OnDupACK()
	nr.OnFastRetransmit(8000)

	before := nr.SendWindow()
	// Additional dup ACKs during recovery inflate cwnd
	nr.OnDupACK()
	if nr.SendWindow() != before+1000 {
		t.Errorf("recovery inflation: cwnd = %d, want %d", nr.SendWindow(), before+1000)
	}
}

func TestNewRenoExitRecovery(t *testing.T) {
	nr := NewNewReno(1000)
	nr.cwnd = 10000
	nr.OnDupACK()
	nr.OnDupACK()
	nr.OnDupACK()
	nr.OnFastRetransmit(8000)

	nr.ExitRecovery()
	// cwnd should deflate to ssthresh
	if nr.SendWindow() != nr.SSThresh() {
		t.Errorf("after exit recovery: cwnd = %d, want ssthresh = %d", nr.SendWindow(), nr.SSThresh())
	}
	if nr.InRecovery() {
		t.Error("should not be in recovery after exit")
	}
}

func TestNewRenoTimeout(t *testing.T) {
	nr := NewNewReno(1000)
	nr.cwnd = 10000

	nr.OnTimeout()
	// ssthresh = max(cwnd/2, 2*MSS) = max(5000, 2000) = 5000
	if nr.SSThresh() != 5000 {
		t.Errorf("ssthresh after timeout = %d, want 5000", nr.SSThresh())
	}
	// cwnd = 1 MSS
	if nr.SendWindow() != 1000 {
		t.Errorf("cwnd after timeout = %d, want 1000", nr.SendWindow())
	}
	if nr.InRecovery() {
		t.Error("should not be in recovery after timeout")
	}
}

func TestNewRenoDupACKBelow3(t *testing.T) {
	nr := NewNewReno(1000)
	if nr.OnDupACK() {
		t.Error("1st dup ACK should not trigger")
	}
	if nr.OnDupACK() {
		t.Error("2nd dup ACK should not trigger")
	}
}

func TestNewRenoACKResetsDupCount(t *testing.T) {
	nr := NewNewReno(1000)
	nr.OnDupACK()
	nr.OnDupACK()
	nr.OnACK(1000) // resets dup count

	if nr.OnDupACK() {
		t.Error("dup ACK after ACK should not trigger (count was reset)")
	}
}
