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
		lowerName := strings.ToLower(d.Name)
		if strings.HasPrefix(lowerName, "docker") || 
		   strings.HasPrefix(lowerName, "br-") || 
		   strings.HasPrefix(lowerName, "veth") ||
		   strings.HasPrefix(lowerName, "lo") { continue }

		desc := d.Description
		if desc == "" { desc = d.Name }

		for _, address := range d.Addresses {
			ip := address.IP.To4()
			if ip == nil || ip.IsLoopback() || strings.HasPrefix(ip.String(), "169.254") || strings.HasPrefix(ip.String(), "127.") { continue }
			
			mac, _ := getMacAddrByIP(ip)
			if len(ip) == 4 {
				ifaces = append(ifaces, NetworkInterface{
					Name:        d.Name,
					Description: desc,
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
	return &Scanner{InterfaceName: iface.Name, MyIP: iface.IP, MyMAC: iface.MAC}, nil
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

	// LISTENER (IPv4 ARP & IPv6 Traffic)
	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		in := src.Packets()
		
		for {
			select {
			case <-ctx.Done(): return
			case packet, ok := <-in:
				if !ok { return }
				
				// 1. Check ARP (IPv4 Discovery)
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					arp, _ := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply {
						senderIP := net.IP(arp.SourceProtAddress)
						senderMAC := net.HardwareAddr(arp.SourceHwAddress)
						if senderIP.Equal(s.MyIP) { continue }
						
						select {
						case results <- models.Device{IP: senderIP, MAC: senderMAC}:
						case <-ctx.Done(): return
						}
					}
				}

				// 2. Check IPv6 (Passive Discovery)

				ip6Layer := packet.Layer(layers.LayerTypeIPv6)
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				
				if ip6Layer != nil && ethLayer != nil {
					ip6, _ := ip6Layer.(*layers.IPv6)
					eth, _ := ethLayer.(*layers.Ethernet)

					if ip6.SrcIP.IsMulticast() || ip6.SrcIP.IsUnspecified() { continue }
					if bytesEqual(eth.SrcMAC, s.MyMAC) { continue }

					select {
					case results <- models.Device{
						IP: nil,
						IPv6: ip6.SrcIP, 
						MAC: eth.SrcMAC,
					}:
					case <-ctx.Done(): return
					}
				}
			}
		}
	}()

	// BROADCASTER (ARP REQUEST)
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
					time.Sleep(2 * time.Millisecond)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	<-ctx.Done()
	wg.Wait()
	close(results)

	// DEDUPLICATE RESULTS (BOTH IPv4 & IPv6)
	deviceMap := make(map[string]*models.Device)
	
	for d := range results {
		key := d.MAC.String()
		if _, exists := deviceMap[key]; !exists {
			if d.IP != nil {
				deviceMap[key] = &d
			} else {
				deviceMap[key] = &d 
			}
		} else {
			// Update Data
			existing := deviceMap[key]
			if d.IP != nil { existing.IP = d.IP } // Update IPv4
			if len(d.IPv6) > 0 { existing.IPv6 = d.IPv6 } // Update IPv6
		}
	}

	var devices []models.Device
	for _, d := range deviceMap {
		if len(d.IP) > 0 {
			devices = append(devices, *d)
		}
	}
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

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) { return false }
	for i, v := range a { if v != b[i] { return false } }
	return true
}