package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"strconv"
	"strings"

	"github.com/ebfe/scard"
	"github.com/ethereum/go-ethereum/log"
	"github.com/status-im/hardware-wallet-go/lightwallet/actionsets"
)

type commandFunc func(*actionsets.Installer) error

var (
	logger = log.New("package", "status-go/cmd/hardware-wallet-light")

	commands map[string]commandFunc

	flagCommand   = flag.String("c", "", "command")
	flagCapFile   = flag.String("f", "", "cap file path")
	flagOverwrite = flag.Bool("o", false, "overwrite applet if already installed")
	flagLogLevel  = flag.String("l", "", `Log level, one of: "ERROR", "WARN", "INFO", "DEBUG", and "TRACE"`)
)

func initLogger() {
	if *flagLogLevel == "" {
		*flagLogLevel = "info"
	}

	level, err := log.LvlFromString(strings.ToLower(*flagLogLevel))
	if err != nil {
		stdlog.Fatal(err)
	}

	handler := log.StreamHandler(os.Stderr, log.TerminalFormat(true))
	filteredHandler := log.LvlFilterHandler(level, handler)
	log.Root().SetHandler(filteredHandler)
}

func init() {
	flag.Parse()
	initLogger()

	commands = map[string]commandFunc{
		"install": commandInstall,
		"info":    commandInfo,
		"delete":  commandDelete,
		"init":    commandInit,
		"pair":    commandPair,
		"status":  commandStatus,
	}
}

func usage() {
	fmt.Printf("\nUsage: hardware-wallet-light COMMAND [FLAGS]\n\nValid commands:\n\n")
	for name := range commands {
		fmt.Printf("- %s\n", name)
	}
	fmt.Print("\nFlags:\n\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func fail(msg string, ctx ...interface{}) {
	logger.Error(msg, ctx...)
	os.Exit(1)
}

func main() {
	if *flagCommand == "" {
		logger.Error("you must specify a command")
		usage()
	}

	ctx, err := scard.EstablishContext()
	if err != nil {
		fail("error establishing card context", "error", err)
	}
	defer func() {
		if err := ctx.Release(); err != nil {
			logger.Error("error releasing context", "error", err)
		}
	}()

	readers, err := ctx.ListReaders()
	if err != nil {
		fail("error getting readers", "error", err)
	}

	if len(readers) == 0 {
		fail("couldn't find any reader")
	}

	if len(readers) > 1 {
		fail("too many readers found")
	}

	reader := readers[0]
	logger.Debug("using reader", "name", reader)
	logger.Debug("connecting to card", "reader", reader)
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fail("error connecting to card", "error", err)
	}
	defer func() {
		if err := card.Disconnect(scard.ResetCard); err != nil {
			logger.Error("error disconnecting card", "error", err)
		}
	}()

	status, err := card.Status()
	if err != nil {
		fail("error getting card status", "error", err)
	}

	switch status.ActiveProtocol {
	case scard.ProtocolT0:
		logger.Debug("card protocol", "T", "0")
	case scard.ProtocolT1:
		logger.Debug("card protocol", "T", "1")
	default:
		logger.Debug("card protocol", "T", "unknown")
	}

	i := actionsets.NewInstaller(card)
	if f, ok := commands[*flagCommand]; ok {
		err = f(i)
		if err != nil {
			logger.Error("error executing command", "command", *flagCommand, "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	fail("unknown command", "command", *flagCommand)
	usage()
}

func ask(description string) string {
	r := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", description)
	text, err := r.ReadString('\n')
	if err != nil {
		stdlog.Fatal(err)
	}

	return strings.TrimSpace(text)
}

func askHex(description string) []byte {
	s := ask(description)
	if s[:2] == "0x" {
		s = s[2:]
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		stdlog.Fatal(err)
	}

	return data
}

func askUint8(description string) uint8 {
	s := ask(description)
	i, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		stdlog.Fatal(err)
	}

	return uint8(i)
}

func commandInstall(i *actionsets.Installer) error {
	if *flagCapFile == "" {
		logger.Error("you must specify a cap file path with the -f flag\n")
		usage()
	}

	f, err := os.Open(*flagCapFile)
	if err != nil {
		fail("error opening cap file", "error", err)
	}
	defer f.Close()

	fmt.Printf("installation can take a while...\n")
	err = i.Install(f, *flagOverwrite)
	if err != nil {
		fail("installation error", "error", err)
	}

	fmt.Printf("applet installed successfully.\n")
	return nil
}

func commandInfo(i *actionsets.Installer) error {
	info, err := i.Info()
	if err != nil {
		return err
	}

	fmt.Printf("Installed: %+v\n", info.Installed)
	fmt.Printf("Initialized: %+v\n", info.Initialized)
	fmt.Printf("InstanceUID: 0x%x\n", info.InstanceUID)
	fmt.Printf("PublicKey: 0x%x\n", info.PublicKey)
	fmt.Printf("Version: 0x%x\n", info.Version)
	fmt.Printf("AvailableSlots: 0x%x\n", info.AvailableSlots)
	fmt.Printf("KeyUID: 0x%x\n", info.KeyUID)

	return nil
}

func commandDelete(i *actionsets.Installer) error {
	err := i.Delete()
	if err != nil {
		return err
	}

	fmt.Printf("applet deleted\n")

	return nil
}

func commandInit(i *actionsets.Installer) error {
	secrets, err := i.Init()
	if err != nil {
		return err
	}

	fmt.Printf("PIN %s\n", secrets.Pin())
	fmt.Printf("PUK %s\n", secrets.Puk())
	fmt.Printf("Pairing password: %s\n", secrets.PairingPass())

	return nil
}

func commandPair(i *actionsets.Installer) error {
	pairingPass := ask("Pairing password")
	pin := ask("PIN")
	info, err := i.Pair(pairingPass, pin)
	if err != nil {
		return err
	}

	fmt.Printf("Pairing key 0x%x\n", info.Key)
	fmt.Printf("Pairing Index %d\n", info.Index)

	return nil
}

func commandStatus(i *actionsets.Installer) error {
	index := askUint8("Pairing index")
	key := askHex("Pairing key")

	return i.Status(index, key)
}
