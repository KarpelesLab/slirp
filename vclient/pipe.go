package vclient

import (
	"encoding/binary"

	"github.com/KarpelesLab/slirp"
)

// Pipe creates a Client wired to a slirp Stack. Frames sent by the client
// are stripped of their Ethernet header and fed to the stack's HandlePacket.
// Responses from the stack are delivered to the client's HandleFrame.
//
// The gwMAC is pre-configured in the ARP table so no ARP resolution is needed.
// Use SetIP/SetDNS after Pipe to configure the client's network.
func Pipe(stack *slirp.Stack, namespace uintptr, clientMAC, gwMAC [6]byte) *Client {
	c := New(clientMAC, nil) // writer set below

	// Pre-configure gateway MAC in ARP table (slirp doesn't do ARP)
	c.arpMu.Lock()
	// Set a catch-all: any IP resolves to gwMAC in the Pipe context
	c.arpTable[[4]byte{0, 0, 0, 0}] = gwMAC // sentinel for getGatewayMAC
	c.arpMu.Unlock()

	c.SetWriter(func(frame []byte) error {
		if len(frame) < 14 {
			return nil
		}
		etherType := binary.BigEndian.Uint16(frame[12:14])
		switch etherType {
		case 0x0800, 0x86DD: // IPv4, IPv6
			return stack.HandlePacket(namespace, clientMAC, gwMAC, frame[14:], c.HandleFrame)
		case 0x0806: // ARP — slirp doesn't handle ARP, silently drop
			return nil
		}
		return nil
	})

	return c
}
