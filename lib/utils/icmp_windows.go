//go:build windows

package utils

import (
	"context"
	"net"
	"syscall"
	"unsafe"
)

const (
	// Completely magic variables used for raw Windows ICMP sockets
	SIO_RCVALL = syscall.IOC_IN | syscall.IOC_VENDOR | 1

	RCVALL_OFF             = 0
	RCVALL_ON              = 1
	RCVALL_SOCKETLEVELONLY = 2
	RCVALL_IPLEVEL         = 3
)

/*
	Creates and returns an ICMP connection to read from and write to.

	See the issue about creating an ICMP listener on Windows:
		- https://github.com/golang/go/issues/38427
	ICMP listener hacky workaround taken from:
		- https://github.com/safing/portmaster/blob/e9881e2f15affbc0c6023278e69268dd0e523f47/netenv/location_windows.go#L21

	All ye beware, for Windows magic lies below.
*/
func ListenICMP(listenAddress string) (net.PacketConn, error) {
	// Listen for ICMP messages
	// https://pkg.go.dev/golang.org/x/net/icmp#ListenPacket

	var conn net.PacketConn
	var err error

	var socketHandle syscall.Handle
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(s uintptr) {
				socketHandle = syscall.Handle(s)
			})
		},
	}

	conn, err = cfg.ListenPacket(context.Background(), "ip4:icmp", listenAddress)

	if err != nil {
		return conn, err
	}

	unused := uint32(0) // Documentation states that this is unused, but WSAIoctl fails without it.
	flag := uint32(RCVALL_IPLEVEL)
	size := uint32(unsafe.Sizeof(flag))
	err = syscall.WSAIoctl(socketHandle, SIO_RCVALL, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &unused, nil, 0)

	return conn, err
}
