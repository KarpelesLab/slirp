package vtcp

import "testing"

func TestNewRenoInitialWindow(t *testing.T) {
	nr := NewNewReno(1460)
	// RFC 6928: initial cwnd = min(10*MSS, max(2*MSS, 14600))
	// 10*1460 = 14600, max(2*1460, 14600) = 14600
	// min(14600, 14600) = 14600
	if nr.SendWindow() != 14600 {
		t.Errorf("initial cwnd = %d, want 14600", nr.SendWindow())
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
	nr.OnFastRetransmit(8000, 10000) // flight size = 8000
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
	nr.OnFastRetransmit(8000, 10000)

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
	nr.OnFastRetransmit(8000, 10000)

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

// --- HighSpeed TCP (RFC 3649) tests ---

func TestHighSpeedInitialWindow(t *testing.T) {
	hs := NewHighSpeed(1460)
	if hs.SendWindow() != 14600 {
		t.Errorf("initial cwnd = %d, want 14600", hs.SendWindow())
	}
}

func TestHighSpeedSlowStart(t *testing.T) {
	hs := NewHighSpeed(1000)
	initial := hs.SendWindow()
	hs.OnACK(1000)
	if hs.SendWindow() != initial+1000 {
		t.Errorf("slow start: cwnd = %d, want %d", hs.SendWindow(), initial+1000)
	}
}

func TestHighSpeedCongestionAvoidance(t *testing.T) {
	hs := NewHighSpeed(1000)
	// Force into congestion avoidance with a large window
	hs.ssthresh = 50000
	hs.cwnd = 100000 // 100 segments — above Low_Window (38)

	before := hs.SendWindow()
	hs.OnACK(1000)
	after := hs.SendWindow()

	// HighSpeed should increase faster than NewReno for large windows
	inc := after - before
	// Standard NewReno would add MSS^2/cwnd = 1000000/100000 = 10
	// HighSpeed should add more due to a(w) > 1 for w > 38 segments
	if inc <= 10 {
		t.Errorf("HSTCP increase = %d, expected > 10 (standard TCP) for large window", inc)
	}
}

func TestHighSpeedSmallWindowMatchesStandard(t *testing.T) {
	// Below Low_Window (38 segments), HSTCP should behave like NewReno
	hs := NewHighSpeed(1000)
	hs.ssthresh = 20000
	hs.cwnd = 20000 // 20 segments < 38

	nr := NewNewReno(1000)
	nr.ssthresh = 20000
	nr.cwnd = 20000

	hs.OnACK(1000)
	nr.OnACK(1000)

	// Should be identical
	if hs.SendWindow() != nr.SendWindow() {
		t.Errorf("HSTCP cwnd=%d, NewReno cwnd=%d — should match for small window",
			hs.SendWindow(), nr.SendWindow())
	}
}

func TestHighSpeedDecrease(t *testing.T) {
	hs := NewHighSpeed(1000)
	hs.cwnd = 100000 // 100 segments

	// Fast retransmit: decrease should be less than 50% for large windows
	hs.OnDupACK()
	hs.OnDupACK()
	hs.OnDupACK()
	hs.OnFastRetransmit(80000, 100000)

	// b(100) ≈ 0.38, so ssthresh ≈ (1-0.38)*100000 = 62000
	// Standard TCP would give 50000
	if hs.SSThresh() <= 50000 {
		t.Errorf("HSTCP ssthresh = %d, expected > 50000 (less decrease than standard)", hs.SSThresh())
	}
}

func TestHighSpeedTimeout(t *testing.T) {
	hs := NewHighSpeed(1000)
	hs.cwnd = 100000

	hs.OnTimeout()
	// cwnd should reset to 1 MSS
	if hs.SendWindow() != 1000 {
		t.Errorf("cwnd after timeout = %d, want 1000", hs.SendWindow())
	}
	// ssthresh should be (1-b(w))*cwnd, higher than standard's cwnd/2
	if hs.SSThresh() <= 50000 {
		t.Errorf("HSTCP ssthresh = %d, expected > 50000", hs.SSThresh())
	}
}

func TestHstcpAB(t *testing.T) {
	// Below Low_Window: standard values
	if a := hstcpA(10); a != 1.0 {
		t.Errorf("a(10) = %f, want 1.0", a)
	}
	if b := hstcpB(10); b != 0.5 {
		t.Errorf("b(10) = %f, want 0.5", b)
	}

	// Above Low_Window: a > 1, b < 0.5
	a := hstcpA(1000)
	if a <= 1.0 {
		t.Errorf("a(1000) = %f, expected > 1.0", a)
	}
	b := hstcpB(1000)
	if b >= 0.5 || b <= 0.1 {
		t.Errorf("b(1000) = %f, expected between 0.1 and 0.5", b)
	}
}
