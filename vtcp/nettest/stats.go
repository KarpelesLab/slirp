package nettest

import "sync/atomic"

// Stats tracks packet delivery metrics for one direction of a link.
type Stats struct {
	Sent       atomic.Int64
	Delivered  atomic.Int64
	Dropped    atomic.Int64
	Reordered  atomic.Int64
	Duplicated atomic.Int64
	Bytes      atomic.Int64 // total bytes delivered
}
