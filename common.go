package main

import (
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func getDevice(name ...string) *pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	if len(devices) == 0 {
		return nil
	}
	for _, dev := range devices {
		var addresses []string
		for _, address := range dev.Addresses {
			addresses = append(addresses, address.IP.String())
		}
		if len(addresses) != 0 {
			logger.Infof("Found device %s, Desc: %s", dev.Name, dev.Description)
			logger.Infof("    Address: %s", strings.Join(addresses, ", "))
		} else {
			logger.Debugf("Found device %s, Desc: %s", dev.Name, dev.Description)
		}
	}
	if len(name) == 0 || len(name[0]) == 0 {
		return &devices[0]
	}
	for _, device := range devices {
		if device.Name == name[0] {
			return &device
		}
	}
	return nil
}

type packetHandler func(handle *pcap.Handle, packet gopacket.Packet)

func startCapture(device, filter string, handler packetHandler) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go startCleanTimeoutSeq()
	for packet := range packetSource.Packets() {
		go handler(handle, packet)
	}
}

func startCleanTimeoutSeq() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		now := time.Now().Unix()
		var expired []uint32
		clientConnMap.Range(func(seq uint32, t int64) bool {
			if now-t > 5 {
				expired = append(expired, seq)
			}
			return true
		})
		for _, k := range expired {
			clientConnMap.Delete(k)
		}
	}
}
