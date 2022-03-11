//go:build windows

package utils

import "syscall"

const (
	// Completely magic variables used for raw Windows ICMP sockets
	SIO_RCVALL = syscall.IOC_IN | syscall.IOC_VENDOR | 1

	RCVALL_OFF             = 0
	RCVALL_ON              = 1
	RCVALL_SOCKETLEVELONLY = 2
	RCVALL_IPLEVEL         = 3
)
