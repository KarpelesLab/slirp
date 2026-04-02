package vclient

import (
	"context"
	"encoding/binary"
	"errors"
	"time"
)

// SetGatewayMAC pre-configures the gateway MAC address, bypassing ARP resolution.
func (c *Client) SetGatewayMAC(mac [6]byte) {
	c.arpMu.Lock()
	defer c.arpMu.Unlock()
	c.arpTable[c.gw] = mac
}

// resolveMAC resolves an IP address to a MAC address, using the ARP table
// and sending ARP requests as needed.
func (c *Client) resolveMAC(ctx context.Context, ip [4]byte) ([6]byte, error) {
	// Broadcast address
	if ip == [4]byte{255, 255, 255, 255} {
		return [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
	}

	// Check if destination is on the local subnet
	c.mu.RLock()
	localIP := c.ip
	mask := c.mask
	gw := c.gw
	c.mu.RUnlock()

	// If not on local subnet, resolve the gateway instead
	targetIP := ip
	for i := 0; i < 4; i++ {
		if (ip[i] & mask[i]) != (localIP[i] & mask[i]) {
			targetIP = gw
			break
		}
	}

	// Check ARP table
	c.arpMu.Lock()
	mac, ok := c.arpTable[targetIP]
	if ok {
		c.arpMu.Unlock()
		return mac, nil
	}
	// Pipe sentinel: 0.0.0.0 maps to gwMAC for all destinations
	if mac, ok := c.arpTable[[4]byte{0, 0, 0, 0}]; ok {
		c.arpMu.Unlock()
		return mac, nil
	}

	// Register a waiter
	ch := make(chan [6]byte, 1)
	c.arpWait[targetIP] = append(c.arpWait[targetIP], ch)
	c.arpMu.Unlock()

	// Send ARP request
	if err := c.sendARPRequest(targetIP); err != nil {
		return [6]byte{}, err
	}

	// Wait for response with timeout
	select {
	case mac := <-ch:
		return mac, nil
	case <-ctx.Done():
		return [6]byte{}, ctx.Err()
	case <-time.After(3 * time.Second):
		return [6]byte{}, errors.New("ARP resolution timeout")
	}
}

// handleARP processes an incoming ARP frame.
func (c *Client) handleARP(frame []byte) error {
	if len(frame) < 42 { // 14 Ethernet + 28 ARP
		return nil
	}
	arp := frame[14:]

	// Hardware type: Ethernet (1)
	if binary.BigEndian.Uint16(arp[0:2]) != 1 {
		return nil
	}
	// Protocol type: IPv4 (0x0800)
	if binary.BigEndian.Uint16(arp[2:4]) != 0x0800 {
		return nil
	}
	// HLEN=6, PLEN=4
	if arp[4] != 6 || arp[5] != 4 {
		return nil
	}

	oper := binary.BigEndian.Uint16(arp[6:8])
	var senderMAC [6]byte
	copy(senderMAC[:], arp[8:14])
	var senderIP [4]byte
	copy(senderIP[:], arp[14:18])
	var targetIP [4]byte
	copy(targetIP[:], arp[24:28])

	switch oper {
	case 1: // ARP Request
		// If the request is for our IP, send a reply
		c.mu.RLock()
		ourIP := c.ip
		c.mu.RUnlock()

		if targetIP == ourIP {
			return c.sendARPReply(senderIP, senderMAC)
		}

	case 2: // ARP Reply
		// Store in ARP table and notify waiters
		c.arpMu.Lock()
		c.arpTable[senderIP] = senderMAC
		waiters := c.arpWait[senderIP]
		delete(c.arpWait, senderIP)
		c.arpMu.Unlock()

		for _, ch := range waiters {
			select {
			case ch <- senderMAC:
			default:
			}
		}
	}

	return nil
}

// sendARPRequest sends an ARP request for the given IP address.
func (c *Client) sendARPRequest(targetIP [4]byte) error {
	c.mu.RLock()
	localIP := c.ip
	w := c.w
	c.mu.RUnlock()

	if w == nil {
		return errors.New("no writer configured")
	}

	// Build ARP request frame
	frame := make([]byte, 42) // 14 Ethernet + 28 ARP

	// Ethernet header
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(frame[6:12], c.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	// ARP
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)  // Protocol type: IPv4
	arp[4] = 6                                     // HLEN
	arp[5] = 4                                     // PLEN
	binary.BigEndian.PutUint16(arp[6:8], 1)        // Operation: Request
	copy(arp[8:14], c.mac[:])                      // Sender MAC
	copy(arp[14:18], localIP[:])                   // Sender IP
	// Target MAC: 00:00:00:00:00:00 (unknown)
	copy(arp[24:28], targetIP[:])                  // Target IP

	return w(frame)
}

// sendARPReply sends an ARP reply to the given target.
func (c *Client) sendARPReply(targetIP [4]byte, targetMAC [6]byte) error {
	c.mu.RLock()
	localIP := c.ip
	w := c.w
	c.mu.RUnlock()

	if w == nil {
		return errors.New("no writer configured")
	}

	frame := make([]byte, 42)

	// Ethernet header
	copy(frame[0:6], targetMAC[:])
	copy(frame[6:12], c.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	// ARP
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 2) // Operation: Reply
	copy(arp[8:14], c.mac[:])
	copy(arp[14:18], localIP[:])
	copy(arp[18:24], targetMAC[:])
	copy(arp[24:28], targetIP[:])

	return w(frame)
}
