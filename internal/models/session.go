package models

import (
	"net"
	"sync"
	"time"
)

type TargetConfig struct {
	IP        net.IP
	IPv6      net.IP
	MAC       net.HardwareAddr
	Name      string
	
	// Control
	IsBlocked bool
	LimitRate int64
	
	// ATOMIC STATS
	BytesUpTotal   int64
	BytesDownTotal int64
	
	// Cache Speedometer
	LastBytesUp    int64
	LastBytesDown  int64
	DisplayUp      float64
	DisplayDown    float64
	LastCheck      time.Time
	
	LimiterBucket  int64
	
	// Monitoring [NEW]
	HistoryDown    []float64
	HistoryUp      []float64
	TCPCount       int64
	UDPCount       int64
	ICMPCount      int64
	
	Mutex sync.Mutex
}

type SessionManager struct {
	Targets      map[string]*TargetConfig
	IPtoTarget   map[string]*TargetConfig // O(1) Lookup by IP
	IPv6toTarget map[string]*TargetConfig // [NEW] O(1) Lookup by IPv6
	Mutex        sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		Targets:      make(map[string]*TargetConfig),
		IPtoTarget:   make(map[string]*TargetConfig),
		IPv6toTarget: make(map[string]*TargetConfig),
	}
}

// Update AddTarget to add IPv6 support
func (sm *SessionManager) AddTarget(device Device, name string) {
	sm.Mutex.Lock()
	defer sm.Mutex.Unlock()
	
	key := device.MAC.String()
	if _, exists := sm.Targets[key]; !exists {
		t := &TargetConfig{
			IP:        device.IP,
			IPv6:      device.IPv6,
			MAC:       device.MAC,
			Name:      name,
			IsBlocked: false,
			LimitRate: 0,
			LastCheck: time.Now(),
			HistoryDown: make([]float64, 0, 60),
			HistoryUp:   make([]float64, 0, 60),
		}
		sm.Targets[key] = t
		sm.IPtoTarget[device.IP.String()] = t
		if len(device.IPv6) > 0 {
			sm.IPv6toTarget[device.IPv6.String()] = t
		}
	} else {
		// If target already exists, update its IPv6 if provided
		if len(device.IPv6) > 0 {
			// If the existing target already had an IPv6, remove the old entry from the map
			if len(sm.Targets[key].IPv6) > 0 && !sm.Targets[key].IPv6.Equal(device.IPv6) {
				delete(sm.IPv6toTarget, sm.Targets[key].IPv6.String())
			}
			sm.Targets[key].IPv6 = device.IPv6
			sm.IPv6toTarget[device.IPv6.String()] = sm.Targets[key]
		}
	}
}

func (sm *SessionManager) RemoveTarget(mac string) {
	sm.Mutex.Lock()
	defer sm.Mutex.Unlock()
	if t, exists := sm.Targets[mac]; exists {
		delete(sm.IPtoTarget, t.IP.String())
		if len(t.IPv6) > 0 {
			delete(sm.IPv6toTarget, t.IPv6.String())
		}
		delete(sm.Targets, mac)
	}
}

func (sm *SessionManager) GetTarget(mac string) *TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	return sm.Targets[mac]
}

func (sm *SessionManager) GetTargetByIP(ip net.IP) *TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	return sm.IPtoTarget[ip.String()]
}

func (sm *SessionManager) GetTargetByIPv6(ipv6 net.IP) *TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	return sm.IPv6toTarget[ipv6.String()]
}

func (sm *SessionManager) GetAllTargets() []*TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	list := make([]*TargetConfig, 0, len(sm.Targets))
	for _, t := range sm.Targets {
		list = append(list, t)
	}
	return list
}

func (sm *SessionManager) LimitAll(limitKB int64) {
	targets := sm.GetAllTargets()
	for _, t := range targets {
		t.Mutex.Lock()
		t.LimitRate = limitKB * 1024
		t.Mutex.Unlock()
	}
}

func (sm *SessionManager) BlockAll(blocked bool) {
	targets := sm.GetAllTargets()
	for _, t := range targets {
		t.Mutex.Lock()
		t.IsBlocked = blocked
		t.Mutex.Unlock()
	}
}