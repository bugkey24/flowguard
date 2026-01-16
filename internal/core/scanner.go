package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bugkey24/flowguard/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type NetworkInterface struct {
	Name        string
	Description string
	IP          net.IP
	MAC         net.HardwareAddr
}

func GetAvailableInterfaces() ([]NetworkInterface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil { return nil, err }

	var ifaces []NetworkInterface
	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP.To4()
			if ip == nil || ip.IsLoopback() || strings.HasPrefix(ip.String(), "169.254") { continue }
			
			mac, _ := getMacAddrByIP(ip)
			
			if len(ip) == 4 {
				ifaces = append(ifaces, NetworkInterface{
					Name:        d.Name,
					Description: d.Description,
					IP:          ip,
					MAC:         mac,
				})
			}
		}
	}
	return ifaces, nil
}

type Scanner struct {
	InterfaceName string
	MyIP          net.IP
	MyMAC         net.HardwareAddr
}

func NewScanner(iface NetworkInterface) (*Scanner, error) {
	if len(iface.IP) == 0 { return nil, fmt.Errorf("invalid interface") }
	
	if len(iface.MAC) == 0 {
		mac, err := getMacAddrByIP(iface.IP)
		if err == nil { iface.MAC = mac }
	}

	return &Scanner{
		InterfaceName: iface.Name,
		MyIP:          iface.IP,
		MyMAC:         iface.MAC,
	}, nil
}

func (s *Scanner) Scan(ctx context.Context) ([]models.Device, error) {
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil { return nil, err }
	defer handle.Close()

	ip := s.MyIP.To4()
	mask := net.CIDRMask(24, 32)
	network := ip.Mask(mask)

	results := make(chan models.Device, 255)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		packetChan := src.Packets()
		
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetChan:
				if !ok { return } // Channel closed
				
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil { continue }
				arp, _ := arpLayer.(*layers.ARP)

				if arp.Operation == layers.ARPReply {
					senderIP := net.IP(arp.SourceProtAddress)
					senderMAC := net.HardwareAddr(arp.SourceHwAddress)
					
					if senderIP.Equal(s.MyIP) { continue }
					
					select {
					case results <- models.Device{IP: senderIP, MAC: senderMAC, Vendor: ""}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	go func() {
		for attempt := 0; attempt < 3; attempt++ {
			for i := 1; i < 255; i++ {
				select {
				case <-ctx.Done(): return
				default:
					targetIP := make(net.IP, 4)
					copy(targetIP, network)
					targetIP[3] = byte(i)
					if targetIP.Equal(s.MyIP) { continue }
					sendARPRequest(handle, s.MyMAC, s.MyIP, targetIP)
					time.Sleep(1 * time.Millisecond)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	<-ctx.Done()
	wg.Wait()
	close(results)

	uniqueMap := make(map[string]models.Device)
	for d := range results { uniqueMap[d.IP.String()] = d }
	var devices []models.Device
	for _, d := range uniqueMap { devices = append(devices, d) }
	return devices, nil
}

func sendARPRequest(handle *pcap.Handle, myMAC net.HardwareAddr, myIP, targetIP net.IP) {
	eth := layers.Ethernet{ SrcMAC: myMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP }
	arp := layers.ARP{ AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: []byte(myMAC), SourceProtAddress: []byte(myIP), DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte(targetIP) }
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp)
	_ = handle.WritePacketData(buf.Bytes())
}

func getMacAddrByIP(ip net.IP) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil { return nil, err }
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs { if strings.Contains(addr.String(), ip.String()) { return i.HardwareAddr, nil } }
	}
	return nil, fmt.Errorf("MAC not found")
}