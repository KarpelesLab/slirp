package slirp

import (
	"errors"
	"net"
	"sync"
)

// Listener is a virtual network listener for TCP connections within the slirp stack.
type Listener struct {
	s         *Stack
	addr      *net.TCPAddr
	acceptCh  chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
}

// Listen announces on the virtual network address.
// The network must be "tcp", "tcp4", or "tcp6".
// The address is the virtual IP:port to listen on within the slirp stack.
func (s *Stack) Listen(network, address string) (net.Listener, error) {
	switch network {
	case "tcp6":
		return s.listen6(network, address)
	case "tcp", "tcp4":
		return s.listen4(network, address)
	default:
		return nil, errors.New("only tcp/tcp4/tcp6 supported")
	}
}

func (s *Stack) listen4(network, address string) (*Listener, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listeners == nil {
		s.listeners = make(map[listenerKey]*Listener)
	}

	if len(addr.IP) != 4 && len(addr.IP) != 16 {
		return nil, errors.New("invalid IP address")
	}
	var ip [4]byte
	if len(addr.IP) == 16 {
		copy(ip[:], addr.IP[12:16])
	} else {
		copy(ip[:], addr.IP)
	}

	key := listenerKey{ip: ip, port: uint16(addr.Port)}
	if _, exists := s.listeners[key]; exists {
		return nil, errors.New("address already in use")
	}

	l := &Listener{
		s:        s,
		addr:     addr,
		acceptCh: make(chan net.Conn, 10),
		closeCh:  make(chan struct{}),
	}

	s.listeners[key] = l
	return l, nil
}

func (s *Stack) listen6(network, address string) (*Listener6, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listeners6 == nil {
		s.listeners6 = make(map[listenerKey6]*Listener6)
	}

	var ip [16]byte
	if len(addr.IP) == 16 {
		copy(ip[:], addr.IP)
	} else if len(addr.IP) == 4 {
		ip[10] = 0xff
		ip[11] = 0xff
		copy(ip[12:], addr.IP)
	} else {
		return nil, errors.New("invalid IP address")
	}

	key := listenerKey6{ip: ip, port: uint16(addr.Port)}
	if _, exists := s.listeners6[key]; exists {
		return nil, errors.New("address already in use")
	}

	l := &Listener6{
		s:        s,
		addr:     addr,
		acceptCh: make(chan net.Conn, 10),
		closeCh:  make(chan struct{}),
	}

	s.listeners6[key] = l
	return l, nil
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, errors.New("listener closed")
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		l.s.mu.Lock()
		defer l.s.mu.Unlock()
		var ip [4]byte
		if len(l.addr.IP) == 16 {
			copy(ip[:], l.addr.IP[12:16])
		} else {
			copy(ip[:], l.addr.IP)
		}
		delete(l.s.listeners, listenerKey{ip: ip, port: uint16(l.addr.Port)})
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.addr }

type listenerKey struct {
	ip   [4]byte
	port uint16
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener6) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, errors.New("listener closed")
	}
}

// Close closes the listener.
func (l *Listener6) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		l.s.mu.Lock()
		defer l.s.mu.Unlock()
		var ip [16]byte
		copy(ip[:], l.addr.IP)
		delete(l.s.listeners6, listenerKey6{ip: ip, port: uint16(l.addr.Port)})
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener6) Addr() net.Addr { return l.addr }
