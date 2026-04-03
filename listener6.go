package slirp

import (
	"net"
	"sync"
)

type listenerKey6 struct {
	ip   [16]byte
	port uint16
}

// Listener6 is a virtual network listener for IPv6 TCP connections within the slirp stack.
type Listener6 struct {
	s         *Stack
	addr      *net.TCPAddr
	acceptCh  chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
}
