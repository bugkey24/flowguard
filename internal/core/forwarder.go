package core

import (
	"bytes"
	"net"
	"sync/atomic"
	"time"

	"github.com/bugkey24/flowguard/internal/models"
	"github.com/google/gopacket/pcap"
)

type Forwarder struct {
	Handle       *pcap.Handle
	MyMAC        net.HardwareAddr
	GatewayMAC   net.HardwareAddr
	Session      *models.SessionManager
}

func NewForwarder(handle *pcap.Handle, myMAC, gatewayMAC net.HardwareAddr, session *models.SessionManager) *Forwarder {
	return &Forwarder{
		Handle:     handle,
		MyMAC:      myMAC,
		GatewayMAC: gatewayMAC,
		Session:    session,
	}
}

func (f *Forwarder) StartForwarding(stopChan chan struct{}) {
	limitTicker := time.NewTicker(20 * time.Millisecond) // Higher frequency for smoother limiting
	defer limitTicker.Stop()

	for {
		select {
		case <-stopChan:
			return
		
		case <-limitTicker.C:
			targets := f.Session.GetAllTargets()
			for _, t := range targets {
				t.Mutex.Lock()
				// Token bucket depletion logic: 20ms refresh means divide rate by 50
				t.LimiterBucket = 0 
				t.Mutex.Unlock()
			}

		default:
			data, _, err := f.Handle.ReadPacketData()
			if err != nil { continue }
			
			if len(data) >= 14 && bytes.Equal(data[6:12], f.MyMAC) {
				continue
			}

			if len(data) < 34 || data[12] != 0x08 || data[13] != 0x00 { continue }

			srcIP := net.IP(data[26:30])
			dstIP := net.IP(data[30:34])

			var target *models.TargetConfig
			var isUpload bool
			
			// [NEW] O(1) Lookup
			if t := f.Session.GetTargetByIP(srcIP); t != nil {
				target = t
				isUpload = true
			} else if t := f.Session.GetTargetByIP(dstIP); t != nil {
				target = t
				isUpload = false
			}

			if target == nil { continue }

			target.Mutex.Lock()
			
			// BLOCK
			if target.IsBlocked {
				target.Mutex.Unlock(); continue 
			}
			
			// LIMIT
			if target.LimitRate > 0 {
				refreshIntervalsPerSec := int64(50) // 1s / 20ms
				maxBucketSize := target.LimitRate / refreshIntervalsPerSec
				
				if target.LimiterBucket > maxBucketSize {
					target.Mutex.Unlock(); continue 
				}
				target.LimiterBucket += int64(len(data))
			}
			target.Mutex.Unlock()

			// STATS
			if isUpload {
				atomic.AddInt64(&target.BytesUpTotal, int64(len(data)))
			} else {
				atomic.AddInt64(&target.BytesDownTotal, int64(len(data)))
			}

			// FORWARD
			outPacket := make([]byte, len(data))
			copy(outPacket, data)

			if isUpload {
				copy(outPacket[0:6], f.GatewayMAC); copy(outPacket[6:12], f.MyMAC)
			} else {
				copy(outPacket[0:6], target.MAC); copy(outPacket[6:12], f.MyMAC)
			}
			f.Handle.WritePacketData(outPacket)
		}
	}
}