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
	
	Mutex sync.Mutex
}

type SessionManager struct {
	Targets map[string]*TargetConfig
	Mutex   sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		Targets: make(map[string]*TargetConfig),
	}
}

// Update AddTarget to add IPv6 support
func (sm *SessionManager) AddTarget(device Device, name string) {
	sm.Mutex.Lock()
	defer sm.Mutex.Unlock()
	
	key := device.MAC.String()
	if _, exists := sm.Targets[key]; !exists {
		sm.Targets[key] = &TargetConfig{
			IP:        device.IP,
			IPv6:      device.IPv6,
			MAC:       device.MAC,
			Name:      name,
			IsBlocked: false,
			LimitRate: 0,
			LastCheck: time.Now(),
		}
	} else {
		if len(device.IPv6) > 0 {
			sm.Targets[key].IPv6 = device.IPv6
		}
	}
}

func (sm *SessionManager) RemoveTarget(mac string) {
	sm.Mutex.Lock()
	defer sm.Mutex.Unlock()
	delete(sm.Targets, mac)
}

func (sm *SessionManager) GetTarget(mac string) *TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	return sm.Targets[mac]
}

func (sm *SessionManager) GetTargetByIP(ip net.IP) *TargetConfig {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	for _, t := range sm.Targets {
		if t.IP.Equal(ip) { return t }
	}
	return nil
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