package vclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/KarpelesLab/slirp"
)

// DHCP message types
const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
)

// DHCP option codes
const (
	dhcpOptSubnetMask    = 1
	dhcpOptRouter        = 3
	dhcpOptDNS           = 6
	dhcpOptRequestedIP   = 50
	dhcpOptLeaseTime     = 51
	dhcpOptMessageType   = 53
	dhcpOptServerID      = 54
	dhcpOptParameterList = 55
	dhcpOptEnd           = 255
)

type dhcpResponse struct {
	yourIP   [4]byte
	serverIP [4]byte
	mask     [4]byte
	router   [4]byte
	dns      [][4]byte
	msgType  byte
}

// DHCP performs DHCP discovery to obtain an IP address and network configuration.
// This sends broadcast Ethernet frames and is intended for real networks, not slirp.
func (c *Client) DHCP(ctx context.Context) error {
	// Send DHCP Discover
	xid := slirp.RandUint32()
	discover := c.buildDHCPMessage(dhcpDiscover, xid, [4]byte{}, [4]byte{})
	if err := c.sendDHCPPacket(discover); err != nil {
		return err
	}

	// Wait for Offer
	offer, err := c.waitDHCPResponse(ctx, xid, dhcpOffer)
	if err != nil {
		return err
	}

	// Send DHCP Request
	request := c.buildDHCPMessage(dhcpRequest, xid, offer.yourIP, offer.serverIP)
	if err := c.sendDHCPPacket(request); err != nil {
		return err
	}

	// Wait for ACK
	ack, err := c.waitDHCPResponse(ctx, xid, dhcpAck)
	if err != nil {
		return err
	}

	// Configure client
	c.mu.Lock()
	c.ip = ack.yourIP
	c.mask = ack.mask
	c.gw = ack.router
	c.dns = ack.dns
	c.mu.Unlock()

	return nil
}

func (c *Client) buildDHCPMessage(msgType byte, xid uint32, requestIP, serverIP [4]byte) []byte {
	// DHCP message (minimum 300 bytes for BOOTP compatibility)
	msg := make([]byte, 300)
	msg[0] = 1    // op: BOOTREQUEST
	msg[1] = 1    // htype: Ethernet
	msg[2] = 6    // hlen: MAC length
	msg[3] = 0    // hops
	binary.BigEndian.PutUint32(msg[4:8], xid)
	// secs, flags
	binary.BigEndian.PutUint16(msg[10:12], 0x8000) // broadcast flag
	// ciaddr, yiaddr, siaddr, giaddr all zero
	copy(msg[28:34], c.mac[:]) // chaddr

	// Magic cookie
	off := 236
	copy(msg[off:off+4], []byte{99, 130, 83, 99})
	off += 4

	// Option 53: DHCP Message Type
	msg[off] = dhcpOptMessageType
	msg[off+1] = 1
	msg[off+2] = msgType
	off += 3

	if msgType == dhcpRequest {
		// Option 50: Requested IP
		msg[off] = dhcpOptRequestedIP
		msg[off+1] = 4
		copy(msg[off+2:off+6], requestIP[:])
		off += 6

		// Option 54: Server Identifier
		msg[off] = dhcpOptServerID
		msg[off+1] = 4
		copy(msg[off+2:off+6], serverIP[:])
		off += 6
	}

	// Option 55: Parameter Request List
	msg[off] = dhcpOptParameterList
	msg[off+1] = 3
	msg[off+2] = dhcpOptSubnetMask
	msg[off+3] = dhcpOptRouter
	msg[off+4] = dhcpOptDNS
	off += 5

	// End
	msg[off] = dhcpOptEnd
	off++

	return msg[:off]
}

func (c *Client) sendDHCPPacket(dhcpPayload []byte) error {
	// Build UDP header
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 68)   // src port
	binary.BigEndian.PutUint16(udpHdr[2:4], 67)   // dst port
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(dhcpPayload)))

	// Build IP header
	ipHdr := make([]byte, 20)
	totalLen := 20 + 8 + len(dhcpPayload)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[8] = 64
	ipHdr[9] = 17 // UDP
	copy(ipHdr[12:16], []byte{0, 0, 0, 0})             // src: 0.0.0.0
	copy(ipHdr[16:20], []byte{255, 255, 255, 255})      // dst: broadcast
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], slirp.IPChecksum(ipHdr))

	// UDP checksum
	binary.BigEndian.PutUint16(udpHdr[6:8], 0)
	binary.BigEndian.PutUint16(udpHdr[6:8], slirp.UDPChecksum(ipHdr[12:16], ipHdr[16:20], udpHdr, dhcpPayload))

	// Build full IP packet
	pkt := make([]byte, len(ipHdr)+len(udpHdr)+len(dhcpPayload))
	copy(pkt, ipHdr)
	copy(pkt[len(ipHdr):], udpHdr)
	copy(pkt[len(ipHdr)+len(udpHdr):], dhcpPayload)

	// Build Ethernet frame (broadcast)
	frame := make([]byte, 14+len(pkt))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], c.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], pkt)

	c.mu.RLock()
	w := c.w
	c.mu.RUnlock()
	if w == nil {
		return errors.New("no writer configured")
	}
	return w(frame)
}

func (c *Client) waitDHCPResponse(ctx context.Context, xid uint32, expectedType byte) (*dhcpResponse, error) {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, errors.New("DHCP timeout")
		case data := <-c.dhcpCh:
			resp, err := parseDHCPResponse(data, xid)
			if err != nil {
				continue
			}
			if resp.msgType == expectedType {
				return resp, nil
			}
			if resp.msgType == dhcpNak {
				return nil, errors.New("DHCP NAK received")
			}
		}
	}
}

func parseDHCPResponse(data []byte, xid uint32) (*dhcpResponse, error) {
	if len(data) < 240 {
		return nil, errors.New("DHCP response too short")
	}
	if data[0] != 2 { // op: BOOTREPLY
		return nil, errors.New("not a BOOTP reply")
	}
	respXID := binary.BigEndian.Uint32(data[4:8])
	if respXID != xid {
		return nil, errors.New("XID mismatch")
	}

	resp := &dhcpResponse{}
	copy(resp.yourIP[:], data[16:20])

	// Parse options (starting at offset 236 + 4 byte magic cookie)
	if len(data) < 240 {
		return resp, nil
	}
	// Verify magic cookie
	if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
		return resp, nil
	}

	off := 240
	for off < len(data) {
		opt := data[off]
		if opt == dhcpOptEnd {
			break
		}
		if opt == 0 { // padding
			off++
			continue
		}
		if off+1 >= len(data) {
			break
		}
		l := int(data[off+1])
		if off+2+l > len(data) {
			break
		}
		val := data[off+2 : off+2+l]

		switch opt {
		case dhcpOptMessageType:
			if l >= 1 {
				resp.msgType = val[0]
			}
		case dhcpOptSubnetMask:
			if l >= 4 {
				copy(resp.mask[:], val[:4])
			}
		case dhcpOptRouter:
			if l >= 4 {
				copy(resp.router[:], val[:4])
			}
		case dhcpOptDNS:
			for i := 0; i+3 < l; i += 4 {
				var dns [4]byte
				copy(dns[:], val[i:i+4])
				resp.dns = append(resp.dns, dns)
			}
		case dhcpOptServerID:
			if l >= 4 {
				copy(resp.serverIP[:], val[:4])
			}
		}
		off += 2 + l
	}

	return resp, nil
}

// DHCPResult contains the network configuration obtained via DHCP.
type DHCPResult struct {
	IP      net.IP
	Mask    net.IPMask
	Gateway net.IP
	DNS     []net.IP
}

// DHCPResult returns the current network configuration obtained via DHCP.
func (c *Client) DHCPResult() *DHCPResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := &DHCPResult{
		IP:      net.IP(c.ip[:]).To4(),
		Mask:    net.IPMask(c.mask[:]),
		Gateway: net.IP(c.gw[:]).To4(),
	}
	for _, dns := range c.dns {
		result.DNS = append(result.DNS, net.IP(dns[:]).To4())
	}
	return result
}
