package slirp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Listener is a virtual network listener for TCP connections within the slirp stack.
type Listener struct {
	s         *Stack
	addr      *net.TCPAddr
	acceptCh  chan *VirtualConn
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

	// Convert to [4]byte for IPv4
	if len(addr.IP) != 4 && len(addr.IP) != 16 {
		return nil, errors.New("invalid IP address")
	}
	var ip [4]byte
	if len(addr.IP) == 16 {
		copy(ip[:], addr.IP[12:16]) // Extract IPv4 from IPv6-mapped
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
		acceptCh: make(chan *VirtualConn, 10),
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

	// Convert to [16]byte for IPv6
	var ip [16]byte
	if len(addr.IP) == 16 {
		copy(ip[:], addr.IP)
	} else if len(addr.IP) == 4 {
		// IPv4-mapped IPv6 address
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
		acceptCh: make(chan *VirtualConn6, 10),
		closeCh:  make(chan struct{}),
	}

	s.listeners6[key] = l
	return l, nil
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
		key := listenerKey6{ip: ip, port: uint16(l.addr.Port)}
		delete(l.s.listeners6, key)
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener6) Addr() net.Addr {
	return l.addr
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
		key := listenerKey{ip: ip, port: uint16(l.addr.Port)}
		delete(l.s.listeners, key)
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.addr
}

type listenerKey struct {
	ip   [4]byte
	port uint16
}

// VirtualConn represents a virtual TCP connection within the slirp stack.
type VirtualConn struct {
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr

	// Server->Client communication
	sendMu   sync.Mutex
	sendBuf  []byte
	sendCond *sync.Cond

	// Client->Server communication
	recvMu   sync.Mutex
	recvBuf  []byte
	recvCond *sync.Cond

	// Connection state
	mu         sync.Mutex
	closed     bool
	clientMAC  [6]byte
	gwMAC      [6]byte
	w          Writer
	seq        uint32 // Server's sequence number
	ack        uint32 // Server's acknowledgment number
	clientSeq  uint32 // Expected client sequence
	clientWnd  uint16 // Client's receive window
	lastAct    time.Time
	established bool
}

func newVirtualConn(localIP [4]byte, localPort uint16, remoteIP [4]byte, remotePort uint16, clientMAC, gwMAC [6]byte, w Writer) *VirtualConn {
	vc := &VirtualConn{
		localAddr:  &net.TCPAddr{IP: net.IP(localIP[:]).To4(), Port: int(localPort)},
		remoteAddr: &net.TCPAddr{IP: net.IP(remoteIP[:]).To4(), Port: int(remotePort)},
		clientMAC:  clientMAC,
		gwMAC:      gwMAC,
		w:          w,
		seq:        randUint32(),
		clientWnd:  65535,
		lastAct:    time.Now(),
	}
	vc.sendCond = sync.NewCond(&vc.sendMu)
	vc.recvCond = sync.NewCond(&vc.recvMu)
	return vc
}

// Read reads data from the connection (data received from the client).
func (vc *VirtualConn) Read(b []byte) (int, error) {
	vc.recvMu.Lock()
	defer vc.recvMu.Unlock()

	for len(vc.recvBuf) == 0 {
		vc.mu.Lock()
		closed := vc.closed
		vc.mu.Unlock()

		if closed {
			return 0, io.EOF
		}
		vc.recvCond.Wait()
	}

	n := copy(b, vc.recvBuf)
	vc.recvBuf = vc.recvBuf[n:]
	return n, nil
}

// Write writes data to the connection (data to send to the client).
func (vc *VirtualConn) Write(b []byte) (int, error) {
	vc.mu.Lock()
	if vc.closed {
		vc.mu.Unlock()
		return 0, errors.New("connection closed")
	}
	vc.mu.Unlock()

	vc.sendMu.Lock()
	vc.sendBuf = append(vc.sendBuf, b...)
	vc.sendMu.Unlock()

	// Trigger sending
	go vc.flush()

	return len(b), nil
}

// flush sends queued data to the client.
func (vc *VirtualConn) flush() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if !vc.established {
		return
	}

	vc.sendMu.Lock()
	defer vc.sendMu.Unlock()

	const maxSegment = 1460
	for len(vc.sendBuf) > 0 {
		segment := vc.sendBuf
		if len(segment) > maxSegment {
			segment = segment[:maxSegment]
		}

		// Build and send TCP packet
		pkt := buildTCPPacket(vc.gwMAC, vc.clientMAC,
			[4]byte(vc.localAddr.IP.To4()), [4]byte(vc.remoteAddr.IP.To4()),
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x18, segment) // PSH+ACK

		_ = vc.w(pkt)
		vc.seq += uint32(len(segment))
		vc.sendBuf = vc.sendBuf[len(segment):]
	}
	vc.sendCond.Broadcast()
}

// handleInbound processes an incoming packet from the client.
func (vc *VirtualConn) handleInbound(ip []byte) error {
	ihl := int(ip[0]&0x0F) * 4
	tcp := ip[ihl:]
	doff := int((tcp[12]>>4)&0x0F) * 4
	if len(tcp) < doff {
		return nil
	}

	flags := tcp[13]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	wnd := binary.BigEndian.Uint16(tcp[14:16])
	payload := tcp[doff:]

	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.lastAct = time.Now()
	if wnd != 0 {
		vc.clientWnd = wnd
	}

	// Handle SYN (should already be handled, but complete handshake)
	if !vc.established && (flags&0x10) != 0 { // ACK
		if ack == vc.seq+1 {
			vc.established = true
			vc.seq += 1 // SYN consumed
		}
		return nil
	}

	// Handle data
	if len(payload) > 0 && seq == vc.clientSeq {
		vc.recvMu.Lock()
		vc.recvBuf = append(vc.recvBuf, payload...)
		vc.recvMu.Unlock()
		vc.recvCond.Broadcast()

		vc.clientSeq += uint32(len(payload))
		vc.ack = vc.clientSeq

		// Send ACK
		pkt := buildTCPPacket(vc.gwMAC, vc.clientMAC,
			[4]byte(vc.localAddr.IP.To4()), [4]byte(vc.remoteAddr.IP.To4()),
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x10, nil) // ACK
		_ = vc.w(pkt)
	}

	// Handle ACK for our data
	if (flags&0x10) != 0 && len(payload) == 0 {
		// Client acknowledged our data
		// Nothing special to do here
	}

	// Handle FIN
	if (flags & 0x01) != 0 {
		vc.clientSeq += 1
		vc.ack = vc.clientSeq
		vc.closed = true

		// Send FIN+ACK
		pkt := buildTCPPacket(vc.gwMAC, vc.clientMAC,
			[4]byte(vc.localAddr.IP.To4()), [4]byte(vc.remoteAddr.IP.To4()),
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x11, nil) // FIN+ACK
		_ = vc.w(pkt)

		vc.recvCond.Broadcast()
		vc.sendCond.Broadcast()
	}

	return nil
}

// Close closes the connection.
func (vc *VirtualConn) Close() error {
	vc.mu.Lock()
	if vc.closed {
		vc.mu.Unlock()
		return nil
	}
	vc.closed = true
	vc.mu.Unlock()

	// Send FIN
	if vc.established {
		pkt := buildTCPPacket(vc.gwMAC, vc.clientMAC,
			[4]byte(vc.localAddr.IP.To4()), [4]byte(vc.remoteAddr.IP.To4()),
			uint16(vc.localAddr.Port), uint16(vc.remoteAddr.Port),
			vc.seq, vc.ack, 0x11, nil) // FIN+ACK
		_ = vc.w(pkt)
	}

	vc.recvCond.Broadcast()
	vc.sendCond.Broadcast()
	return nil
}

// LocalAddr returns the local network address.
func (vc *VirtualConn) LocalAddr() net.Addr {
	return vc.localAddr
}

// RemoteAddr returns the remote network address.
func (vc *VirtualConn) RemoteAddr() net.Addr {
	return vc.remoteAddr
}

// SetDeadline sets the read and write deadlines (not implemented).
func (vc *VirtualConn) SetDeadline(t time.Time) error {
	return nil // Not implemented for now
}

// SetReadDeadline sets the read deadline (not implemented).
func (vc *VirtualConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for now
}

// SetWriteDeadline sets the write deadline (not implemented).
func (vc *VirtualConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for now
}
