package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/nadoo/ipset"
)

// set[ip]
var serverConnSet SyncSet[string]

// map[seq]time
var clientConnMap SyncMap[uint32, int64]

func onTCPPacketReceive(handle *pcap.Handle, packet gopacket.Packet) {
	var srcIP net.IP
	var dstIP net.IP
	mask := 32
	if l3 := packet.Layer(layers.LayerTypeIPv4); l3 != nil {
		l3 := l3.(*layers.IPv4)
		srcIP = l3.SrcIP
		dstIP = l3.DstIP
	} else if l3 := packet.Layer(layers.LayerTypeIPv6); l3 != nil {
		l3 := l3.(*layers.IPv6)
		mask = 128
		srcIP = l3.SrcIP
		dstIP = l3.DstIP
	} else {
		panic("unknown type layer 3")
	}
	ipStr := srcIP.String()
	l4p := packet.Layer(layers.LayerTypeTCP)
	if l4p == nil {
		return
	}
	l4 := l4p.(*layers.TCP)
	switch {
	case l4.SYN && l4.ACK:
		// server's first packet, if the next is RST, handle it, otherwise, drop it
		serverSeq := l4.Seq
		logger.Debugf("Receive SYNC packet from %s, seq: %d", ipStr, serverSeq)
		serverConnSet.Add(ipStr)
	case l4.SYN:
		// client's first packet, record it to log domain
		clientConnMap.Store(l4.Seq, time.Now().Unix())
	default:
		if ok := serverConnSet.CheckAndRemove(ipStr); ok {
			if l4.RST {
				netStr := fmt.Sprintf("%s/%d", ipStr, mask)
				logger.Infof("ipset add %s %s", setName, netStr)
				err := ipset.Add(setName, netStr)
				if err != nil {
					logger.Warnf("Failed to add %s to ipset %s: %s", ipStr, setName, err)
				}
				err = db.SetDomainRST(ipStr)
				if err != nil {
					logger.Warnf("Failed to update rst for %s in db: %s", ipStr, err)
				}
			}
		}
		// check client hello for domain
		synSeq := l4.Seq - 1
		if _, ok := clientConnMap.LoadAndDelete(synSeq); ok {
			domain := extractDomainFromPayload(l4.Payload)
			if len(domain) != 0 {
				ipStr := dstIP.String()
				err := db.AddDomain(ipStr, domain)
				if err != nil {
					logger.Warnf("Failed to insert %s %s to db: %s", ipStr, domain, err)
				}
			}
		}
	}
}

/*
see https://github.com/dlundquist/sniproxy/blob/master/src/tls.c

packet layout:
TLSv1 Record Layer: Handshake Protocol: Client Hello
    Content Type: Handshake (22)
    Version: TLS 1.0 (0x0301)
    Length: 512
    Handshake Protocol: Client Hello
        Handshake Type: Client Hello (1)
        Length: 508
        Version: TLS 1.2 (0x0303)
        Random: 0000000000000000000000000000000000000000000000000000000000000000
        Session ID Length: 32
        Session ID: 0000000000000000000000000000000000000000000000000000000000000000
        Cipher Suites Length: 62
        Cipher Suites (31 suites)
        Compression Methods Length: 1
        Compression Methods (1 method)
        Extensions Length: 373
        Extension: server_name (len=18)
        Extension: ec_point_formats (len=4)
        Extension: supported_groups (len=12)
        Extension: next_protocol_negotiation (len=0)
        Extension: application_layer_protocol_negotiation (len=14)
        Extension: encrypt_then_mac (len=0)
        Extension: extended_master_secret (len=0)
        Extension: post_handshake_auth (len=0)
        Extension: signature_algorithms (len=42)
        Extension: supported_versions (len=5)
        Extension: psk_key_exchange_modes (len=2)
        Extension: key_share (len=38)
        Extension: padding (len=186)
*/
func extractDomainFromPayload(data []byte) string {
	if len(data) == 0 || data[0] != 0x16 {
		// not handshake
		return ""
	}
	if data[0]&0x80 != 0 && data[2] == 1 {
		// not support SNI
		return ""
	}
	// len := int(data[3])<<8 + int(data[4])
	if data[5] != 1 {
		// not client hello
		return ""
	}

	// content type(1)+version(2)+len(2)+handshake type(1)+len(3)+version(2)+random(32)
	offset := 43
	sessionLen := int(data[offset])
	offset += sessionLen + 1
	cipherLen := int(data[offset])<<8 + int(data[offset+1])
	offset += cipherLen + 2
	compressionLen := int(data[offset])
	offset += compressionLen + 1
	// extension len
	offset += 2
	return extractDomainFromExtensions(data[offset:])
}

func extractDomainFromExtensions(data []byte) string {
	offset := 0
	for offset < len(data) {
		typ := int(data[offset])<<8 + int(data[offset+1])
		offset += 2
		fieldLen := int(data[offset])<<8 + int(data[offset+1])
		offset += 2
		if typ == 0 {
			nameType := data[offset+3]
			if nameType == 0 {
				// type hostname
				return string(data[offset+5 : offset+fieldLen])
			} else {
				logger.Warnf("unknown name type %d", nameType)
			}
		}
		offset += fieldLen
	}
	return ""
}
