package vtcp

import "testing"

func TestSeqBefore(t *testing.T) {
	tests := []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true},
		{2, 1, false},
		{1, 1, false},
		{0, 1, true},
		{0xFFFFFFFF, 0, true},  // wraparound: max is before 0
		{0, 0xFFFFFFFF, false}, // 0 is after max
		{0x80000000, 0, true},  // halfway point: int32(0x80000000) < 0
		{0x7FFFFFFF, 0x80000000, true},
	}
	for _, tt := range tests {
		if got := SeqBefore(tt.a, tt.b); got != tt.want {
			t.Errorf("SeqBefore(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSeqAfter(t *testing.T) {
	tests := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{1, 1, false},
		{0, 0xFFFFFFFF, true},  // 0 is after max (wraparound)
		{0xFFFFFFFF, 0, false}, // max is before 0
		{100, 50, true},
	}
	for _, tt := range tests {
		if got := SeqAfter(tt.a, tt.b); got != tt.want {
			t.Errorf("SeqAfter(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSeqBeforeEq(t *testing.T) {
	if !SeqBeforeEq(1, 1) {
		t.Error("SeqBeforeEq(1, 1) should be true")
	}
	if !SeqBeforeEq(1, 2) {
		t.Error("SeqBeforeEq(1, 2) should be true")
	}
	if SeqBeforeEq(2, 1) {
		t.Error("SeqBeforeEq(2, 1) should be false")
	}
}

func TestSeqAfterEq(t *testing.T) {
	if !SeqAfterEq(1, 1) {
		t.Error("SeqAfterEq(1, 1) should be true")
	}
	if !SeqAfterEq(2, 1) {
		t.Error("SeqAfterEq(2, 1) should be true")
	}
	if SeqAfterEq(1, 2) {
		t.Error("SeqAfterEq(1, 2) should be false")
	}
}

func TestSeqInRange(t *testing.T) {
	// [10, 20)
	if !SeqInRange(10, 10, 20) {
		t.Error("10 should be in [10, 20)")
	}
	if !SeqInRange(15, 10, 20) {
		t.Error("15 should be in [10, 20)")
	}
	if SeqInRange(20, 10, 20) {
		t.Error("20 should NOT be in [10, 20)")
	}
	if SeqInRange(9, 10, 20) {
		t.Error("9 should NOT be in [10, 20)")
	}

	// Wraparound: [0xFFFFFFF0, 0x10)
	if !SeqInRange(0xFFFFFFF5, 0xFFFFFFF0, 0x10) {
		t.Error("0xFFFFFFF5 should be in [0xFFFFFFF0, 0x10)")
	}
	if !SeqInRange(0, 0xFFFFFFF0, 0x10) {
		t.Error("0 should be in [0xFFFFFFF0, 0x10)")
	}
	if SeqInRange(0x10, 0xFFFFFFF0, 0x10) {
		t.Error("0x10 should NOT be in [0xFFFFFFF0, 0x10)")
	}
}

func TestSeqInRangeInclusive(t *testing.T) {
	if !SeqInRangeInclusive(20, 10, 20) {
		t.Error("20 should be in [10, 20]")
	}
	if SeqInRangeInclusive(21, 10, 20) {
		t.Error("21 should NOT be in [10, 20]")
	}
}
