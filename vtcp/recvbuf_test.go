package vtcp

import "testing"

func TestRecvBufInOrder(t *testing.T) {
	rb := NewRecvBuf(1000, 0)

	n := rb.Insert(1000, []byte("hello"))
	if n != 5 {
		t.Errorf("Insert = %d, want 5", n)
	}
	if rb.Nxt() != 1005 {
		t.Errorf("Nxt = %d, want 1005", rb.Nxt())
	}
	if rb.Readable() != 5 {
		t.Errorf("Readable = %d, want 5", rb.Readable())
	}

	buf := make([]byte, 10)
	rn := rb.Read(buf)
	if string(buf[:rn]) != "hello" {
		t.Errorf("Read = %q, want %q", buf[:rn], "hello")
	}
}

func TestRecvBufOutOfOrder(t *testing.T) {
	rb := NewRecvBuf(1000, 0)

	// Segment 2 arrives first (out of order)
	n := rb.Insert(1005, []byte("world"))
	if n != 0 {
		t.Errorf("OOO Insert = %d, want 0 (not yet contiguous)", n)
	}
	if rb.Readable() != 0 {
		t.Errorf("Readable = %d, want 0", rb.Readable())
	}
	if !rb.HasOOO() {
		t.Error("should have OOO data")
	}

	// Segment 1 arrives (fills gap)
	n = rb.Insert(1000, []byte("hello"))
	if n != 5 {
		t.Errorf("gap-fill Insert = %d, want 5", n)
	}
	// Both segments should now be readable
	if rb.Readable() != 10 {
		t.Errorf("Readable after fill = %d, want 10", rb.Readable())
	}
	if rb.Nxt() != 1010 {
		t.Errorf("Nxt = %d, want 1010", rb.Nxt())
	}

	buf := make([]byte, 20)
	rn := rb.Read(buf)
	if string(buf[:rn]) != "helloworld" {
		t.Errorf("Read = %q, want %q", buf[:rn], "helloworld")
	}
}

func TestRecvBufDuplicate(t *testing.T) {
	rb := NewRecvBuf(1000, 0)
	rb.Insert(1000, []byte("hello"))

	// Duplicate
	n := rb.Insert(1000, []byte("hello"))
	if n != 0 {
		t.Errorf("duplicate Insert = %d, want 0", n)
	}
	if rb.Readable() != 5 {
		t.Errorf("Readable = %d, want 5", rb.Readable())
	}
}

func TestRecvBufPartialOverlap(t *testing.T) {
	rb := NewRecvBuf(1000, 0)
	rb.Insert(1000, []byte("hel"))

	// Overlapping retransmit
	n := rb.Insert(1002, []byte("lloworld"))
	if n != 7 {
		t.Errorf("overlap Insert = %d, want 7 (new bytes)", n)
	}
	if rb.Nxt() != 1010 {
		t.Errorf("Nxt = %d, want 1010", rb.Nxt())
	}

	buf := make([]byte, 20)
	rn := rb.Read(buf)
	if string(buf[:rn]) != "helloworld" {
		t.Errorf("Read = %q, want %q", buf[:rn], "helloworld")
	}
}

func TestRecvBufMultipleOOO(t *testing.T) {
	rb := NewRecvBuf(1000, 0)

	// Three contiguous out-of-order segments (no gaps between them)
	rb.Insert(1005, []byte("BB")) // 1005-1007
	rb.Insert(1007, []byte("CC")) // 1007-1009
	rb.Insert(1009, []byte("DD")) // 1009-1011

	// Fill the initial gap
	n := rb.Insert(1000, []byte("AAAAA")) // 1000-1005
	if n != 5 {
		t.Errorf("gap-fill = %d, want 5", n)
	}

	// Should now have all data contiguous (1000-1011)
	if rb.Nxt() != 1011 {
		t.Errorf("Nxt = %d, want 1011", rb.Nxt())
	}

	buf := make([]byte, 30)
	rn := rb.Read(buf)
	if string(buf[:rn]) != "AAAAABBCCDD" {
		t.Errorf("Read = %q, want %q", buf[:rn], "AAAAABBCCDD")
	}
}

func TestRecvBufSACKBlocks(t *testing.T) {
	rb := NewRecvBuf(1000, 0)
	rb.Insert(1010, []byte("BB"))
	rb.Insert(1020, []byte("CC"))

	blocks := rb.SACKBlocks()
	if len(blocks) != 2 {
		t.Fatalf("SACK blocks = %d, want 2", len(blocks))
	}
	if blocks[0].Left != 1010 || blocks[0].Right != 1012 {
		t.Errorf("block[0] = (%d,%d), want (1010,1012)", blocks[0].Left, blocks[0].Right)
	}
	if blocks[1].Left != 1020 || blocks[1].Right != 1022 {
		t.Errorf("block[1] = (%d,%d), want (1020,1022)", blocks[1].Left, blocks[1].Right)
	}
}

func TestRecvBufSACKMax3(t *testing.T) {
	rb := NewRecvBuf(1000, 0)
	rb.Insert(1010, []byte("A"))
	rb.Insert(1020, []byte("B"))
	rb.Insert(1030, []byte("C"))
	rb.Insert(1040, []byte("D"))

	blocks := rb.SACKBlocks()
	if len(blocks) != 3 {
		t.Errorf("SACK blocks = %d, want 3 (max)", len(blocks))
	}
}

func TestRecvBufEmpty(t *testing.T) {
	rb := NewRecvBuf(1000, 0)
	n := rb.Insert(1000, nil)
	if n != 0 {
		t.Errorf("nil Insert = %d, want 0", n)
	}
	n = rb.Insert(1000, []byte{})
	if n != 0 {
		t.Errorf("empty Insert = %d, want 0", n)
	}
}

func TestRecvBufSequenceWrap(t *testing.T) {
	rb := NewRecvBuf(0xFFFFFFF0, 0)

	n := rb.Insert(0xFFFFFFF0, []byte("wrap"))
	if n != 4 {
		t.Errorf("Insert = %d, want 4", n)
	}
	if rb.Nxt() != 0xFFFFFFF4 {
		t.Errorf("Nxt = %d, want %d", rb.Nxt(), uint32(0xFFFFFFF4))
	}

	// OOO segment after wrap
	rb.Insert(0xFFFFFFF8, []byte("after"))
	// Fill gap
	n = rb.Insert(0xFFFFFFF4, []byte("XXXX"))
	if n != 4 {
		t.Errorf("gap fill = %d, want 4", n)
	}
	if rb.Nxt() != 0xFFFFFFFD {
		t.Errorf("Nxt after merge = %d, want %d", rb.Nxt(), uint32(0xFFFFFFFD))
	}
}

func TestRecvBufOOOOverlap(t *testing.T) {
	rb := NewRecvBuf(1000, 0)

	// Two overlapping OOO segments
	rb.Insert(1005, []byte("ABCDE"))
	rb.Insert(1008, []byte("DEFGH"))

	// Fill gap
	rb.Insert(1000, []byte("XXXXX"))

	buf := make([]byte, 30)
	rn := rb.Read(buf)
	// 1000-1004: XXXXX, 1005-1009: ABCDE, 1008-1012: DEFGH → merged as ABCDEFGH
	expected := "XXXXXABCDEFGH"
	if string(buf[:rn]) != expected {
		t.Errorf("Read = %q, want %q", buf[:rn], expected)
	}
}
