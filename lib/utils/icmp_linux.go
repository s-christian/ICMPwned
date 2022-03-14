//go:build linux

package utils

import (
	"net"

	"golang.org/x/net/icmp"
)

/*
	Creates and returns an ICMP connection to read from and write to.
*/
func ListenICMP(listenAddress string) (net.PacketConn, error) {
	// Listen for ICMP messages
	// https://pkg.go.dev/golang.org/x/net/icmp#ListenPacket

	var conn net.PacketConn
	var err error

	conn, err = icmp.ListenPacket("ip4:icmp", listenAddress)

	if err != nil {
		return nil, err
	}

	return conn, err
}
