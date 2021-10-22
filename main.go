package main

import (
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/nadoo/ipset"
	"github.com/sirupsen/logrus"
)

var setName string

var opts struct {
	Verbose []bool `short:"v" long:"verbose" description:"Show debug information"`

	InterfaceName string `short:"i" long:"interface" description:"listen interface name" required:"true"`
	SetName       string `short:"s" long:"set-name" description:"ipset name" required:"true"`
	DBName        string `short:"d" long:"db-name" description:"database name, default is data.db" required:"false"`
}

var db *DB

const defaultDBName = "data.db"

func main() {
	args, err := flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "unknown args: %v", args)
	if len(opts.Verbose) != 0 {
		logger.SetLevel(logrus.DebugLevel)
	}
	dbName := defaultDBName
	if len(opts.DBName) != 0 {
		dbName = opts.DBName
	}
	db, err = OpenDB(dbName)
	if err != nil {
		panic(err)
	}
	if err := ipset.Init(); err != nil {
		logger.Errorf("failed to init ipset: %s", err)
		return
	}
	setName = opts.SetName
	interfaceName := opts.InterfaceName
	device := getDevice(interfaceName)
	if device == nil {
		logger.Errorf("Failed to get device %s", interfaceName)
		return
	}
	startCapture(interfaceName, "tcp and port 443", onTCPPacketReceive)
}
