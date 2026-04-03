package vtcp

import (
	"testing"
	"time"
)

func TestRTOInitial(t *testing.T) {
	r := NewRTOCalculator()
	if r.RTO() != DefaultRTO {
		t.Errorf("initial RTO = %v, want %v", r.RTO(), DefaultRTO)
	}
}

func TestRTOFirstSample(t *testing.T) {
	r := NewRTOCalculator()
	r.Sample(100 * time.Millisecond)

	// SRTT = R = 100ms
	// RTTVAR = R/2 = 50ms
	// RTO = SRTT + 4*RTTVAR = 100 + 200 = 300ms
	if r.SRTT() != 100*time.Millisecond {
		t.Errorf("SRTT = %v, want 100ms", r.SRTT())
	}
	if r.RTO() != 300*time.Millisecond {
		t.Errorf("RTO = %v, want 300ms", r.RTO())
	}
}

func TestRTOSubsequentSample(t *testing.T) {
	r := NewRTOCalculator()
	r.Sample(100 * time.Millisecond)
	r.Sample(120 * time.Millisecond)

	// After second sample:
	// RTTVAR = (3*50ms + |100ms - 120ms|) / 4 = (150ms + 20ms) / 4 = 42.5ms
	// SRTT = (7*100ms + 120ms) / 8 = 820ms / 8 = 102.5ms
	// RTO = 102.5ms + 4*42.5ms = 272.5ms → clamped to min 200ms
	if r.RTO() < MinRTO {
		t.Errorf("RTO %v should be >= MinRTO %v", r.RTO(), MinRTO)
	}
}

func TestRTOBackoff(t *testing.T) {
	r := NewRTOCalculator()
	r.Sample(100 * time.Millisecond)
	rto1 := r.RTO()

	r.Backoff()
	if r.RTO() != rto1*2 {
		t.Errorf("after backoff: RTO = %v, want %v", r.RTO(), rto1*2)
	}
}

func TestRTOBackoffCap(t *testing.T) {
	r := NewRTOCalculator()
	// Backoff repeatedly
	for range 20 {
		r.Backoff()
	}
	if r.RTO() > MaxRTO {
		t.Errorf("RTO %v exceeds MaxRTO %v", r.RTO(), MaxRTO)
	}
}

func TestRTOMinClamp(t *testing.T) {
	r := NewRTOCalculator()
	// Very small RTT
	r.Sample(1 * time.Millisecond)
	if r.RTO() < MinRTO {
		t.Errorf("RTO %v below MinRTO %v", r.RTO(), MinRTO)
	}
}

func TestRTOKarnAlgorithm(t *testing.T) {
	r := NewRTOCalculator()

	// Start timing seq 1000
	r.StartTiming(1000)

	// Invalidate (retransmission happened)
	r.InvalidateTiming()

	// ACK arrives — should NOT take a sample
	sampled := r.AckReceived(1001)
	if sampled {
		t.Error("should not sample after invalidation")
	}
}

func TestRTOTimingNormal(t *testing.T) {
	r := NewRTOCalculator()
	r.StartTiming(1000)

	// Simulate some time passing
	time.Sleep(5 * time.Millisecond)

	// ACK covers the timed segment
	sampled := r.AckReceived(1001)
	if !sampled {
		t.Error("should have sampled")
	}
	if r.SRTT() == 0 {
		t.Error("SRTT should be non-zero after sample")
	}
}

func TestRTOTimingPartialACK(t *testing.T) {
	r := NewRTOCalculator()
	r.StartTiming(1000)

	// ACK doesn't cover the timed segment
	sampled := r.AckReceived(999)
	if sampled {
		t.Error("should not sample for ACK before timed seq")
	}
}

func TestRTOStartTimingOnce(t *testing.T) {
	r := NewRTOCalculator()
	r.StartTiming(1000)
	r.StartTiming(2000) // should be ignored (already timing)

	// ACK for 2000 should not trigger sample (we're timing 1000, not 2000)
	// Actually since we check SeqAfter(ack, timeSeq), ack=2001 > timeSeq=1000 → would sample
	// But the point is StartTiming(2000) was ignored, so timeSeq is still 1000
	sampled := r.AckReceived(1001)
	if !sampled {
		t.Error("should sample for ACK after original timed seq")
	}
}
