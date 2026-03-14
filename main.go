package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bugkey24/flowguard/internal/core"
	"github.com/bugkey24/flowguard/internal/models"
	"github.com/bugkey24/flowguard/internal/utils"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/pcap"
)

// --- STYLES ---
var (
	accentColor = lipgloss.Color("#7D56F4")
	roseColor   = lipgloss.Color("#F43F5E")
	tealColor   = lipgloss.Color("#10B981")
	goldColor   = lipgloss.Color("#FFD700")

	tealStyle = lipgloss.NewStyle().Foreground(tealColor).Bold(true)
	goldStyle = lipgloss.NewStyle().Foreground(goldColor)
	roseStyle = lipgloss.NewStyle().Foreground(roseColor)

	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Margin(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(accentColor).
			Padding(0, 2).
			Height(1).
			Align(lipgloss.Center)

	bannerStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true).
			Margin(1, 0, 1, 4)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Margin(0, 2)

	logStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("238")).
			Margin(0, 1). // Reduced margin
			Padding(0, 1).
			Height(5).
			Width(90)
)

const banner = `
  ______   _                                                _ 
 |  ____| | |                                              | |
 | |__    | |   ___   __      __   __ _   _   _    __ _   _ __   __| |
 |  __|   | |  / _ \  \ \ /\ / /  / _' | | | | |  / _' | | '__| / _' |
 | |      | | | (_) |  \ V  V /  | (_| | | |_| | | (_| | | |   | (_| |
 |_|      |_|  \___/    \_/\_/    \__, |  \__,_|  \__,_| |_|    \__,_|
                                   __/ |                              
                                  |___/                               
`

// --- MODEL ---
type model struct {
	state       string // "iface_select", "scanning", "running", "renaming"
	
	// Interface Selection
	interfaces    []core.NetworkInterface
	ifaceTable    table.Model
	selectedIface core.NetworkInterface

	// Core Components
	scanner     *core.Scanner
	devices     []models.Device
	aliases     utils.AliasMap
	table       table.Model
	textInput   textinput.Model

	session     *models.SessionManager
	spoofer     *core.Spoofer
	spoofer6    *core.Spoofer6
	forwarder   *core.Forwarder
	stopChan    chan struct{}
	
	// Network Info
	gatewayIP   net.IP
	gatewayMAC  net.HardwareAddr
	ifaceIndex  int
	selectedMAC net.HardwareAddr
	err         error
	
	// UI Flags
	skipTableUpdate bool 
	logs            []string // [NEW] Monitoring Logs
}

// Messages
type ifaceListMsg []core.NetworkInterface
type scanResultMsg struct {
	devices []models.Device
	scanner *core.Scanner
}
type engineReadyMsg struct {
	spoofer   *core.Spoofer
	spoofer6  *core.Spoofer6
	forwarder *core.Forwarder
	stopChan  chan struct{}
	err       error
}
type tickMsg time.Time

func initialModel() model {
	// 1. Setup Table Utama (Device List)
	columns := []table.Column{
		{Title: "IP Address", Width: 15},
		{Title: "Name / Vendor", Width: 20},
		{Title: "Download", Width: 12},
		{Title: "Upload", Width: 12},
		{Title: "Status / Action", Width: 15},
	}
	t := table.New(table.WithColumns(columns), table.WithFocused(true), table.WithHeight(15))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(false)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	t.SetStyles(s)

	// 2. Setup Table Interface Selection
	colsIface := []table.Column{
		{Title: "Interface Name / Desc", Width: 40},
		{Title: "IP Address", Width: 15},
		{Title: "MAC Address", Width: 20},
	}
	tIface := table.New(table.WithColumns(colsIface), table.WithFocused(true), table.WithHeight(6))
	tIface.SetStyles(s)

	// 3. Input Component
	ti := textinput.New()
	ti.Placeholder = "Enter device name..."
	ti.CharLimit = 30
	ti.Width = 40

	aliases, _ := utils.LoadAliases()
	session := models.NewSessionManager()

	return model{
		state:      "iface_select",
		table:      t,
		ifaceTable: tIface,
		textInput:  ti,
		aliases:    aliases,
		session:    session,
	}
}

func (m model) Init() tea.Cmd {
	return getInterfacesCmd
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.skipTableUpdate = false

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Global Quit
		if m.state != "renaming" && (msg.String() == "q" || msg.String() == "ctrl+c") {
			m.cleanup()
			return m, tea.Quit
		}

		// --- SCREEN 1: SELECT INTERFACE ---
		if m.state == "iface_select" {
			switch msg.String() {
			case "enter":
				idx := m.ifaceTable.Cursor()
				if idx >= 0 && idx < len(m.interfaces) {
					m.selectedIface = m.interfaces[idx]
					m.state = "scanning"
					return m, scanNetworkCmd(m.selectedIface)
				}
			case "up", "k":
				m.ifaceTable.MoveUp(1)
			case "down", "j":
				m.ifaceTable.MoveDown(1)
			}
			return m, nil
		}

		// --- SCREEN 2: RENAME & MONITOR ---
		if m.state == "renaming" || m.state == "monitoring" {
			switch msg.Type {
			case tea.KeyEsc:
				m.state = "running"
				m.textInput.Blur()
				return m, nil
			case tea.KeyEnter:
				if m.state == "renaming" {
					utils.SaveAlias(m.selectedMAC.String(), m.textInput.Value())
					m.aliases, _ = utils.LoadAliases()
					m.state = "running"
					m.refreshTable()
					return m, nil
				}
			}
			if m.state == "renaming" {
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
			return m, nil
		}

		// --- SCREEN 3: MAIN DASHBOARD ---
		if m.state == "running" {
			sel := m.getSelectedDevice()
			
			switch msg.String() {
			case "s":
				m.state = "scanning"
				return m, scanNetworkCmd(m.selectedIface)
			
			case "r":
				if sel != nil {
					m.selectedMAC = sel.MAC
					m.state = "renaming"
					m.textInput.SetValue(m.aliases[sel.MAC.String()])
					m.textInput.Focus()
					return m, textinput.Blink
				}
			
			// --- MASS ACTIONS ---
			case "b": // BLOCK ALL
				m.activateAllDevices()
				m.session.BlockAll(true) // BLOCK ALL
				m.refreshTable()
			case "u": // UNBLOCK ALL
				m.session.BlockAll(false)
				m.refreshTable()
			case "l": // LIMIT ALL
				m.activateAllDevices()
				m.session.LimitAll(50) // 50 KB/s
				m.addLog("⚠️ ALL DEVICES LIMITED TO 50KB/s")
				m.refreshTable()
			
			// --- SINGLE ACTIONS ---
			case "enter":
				m.skipTableUpdate = true
				if sel != nil && !isSafeDevice(sel, m) {
					mac := sel.MAC.String()
					if t := m.session.GetTarget(mac); t != nil {
						m.session.RemoveTarget(mac)
						if m.spoofer != nil { go m.spoofer.RestoreTarget(t) }
					} else {
						m.addToSession(sel)
					}
					m.refreshTable()
				}
			case " ": // SPACE: Block/Unblock
				m.skipTableUpdate = true
				if sel != nil && !isSafeDevice(sel, m) {
					mac := sel.MAC.String()
					t := m.session.GetTarget(mac)
					if t == nil {
						m.addToSession(sel)
						t = m.session.GetTarget(mac)
					}
					// Toggle Status
					t.Mutex.Lock()
					t.IsBlocked = !t.IsBlocked
					status := "BLOCKED"
					if !t.IsBlocked { status = "UNBLOCKED" }
					m.addLog(fmt.Sprintf("🛡️  DEVICE %s %s", t.IP, status))
					t.Mutex.Unlock()
					m.refreshTable()
				}
			case "]": if sel != nil { m.autoLimit(sel, 50) }
			case "[": if sel != nil { m.autoLimit(sel, -50) }
			case "0": if sel != nil { m.autoLimit(sel, -999999) }
			case "t": // Toggle Stealth
				if m.spoofer != nil {
					m.spoofer.Stealth = !m.spoofer.Stealth
					status := "ENABLED"
					if !m.spoofer.Stealth { status = "DISABLED" }
					m.addLog(fmt.Sprintf("🛡️  STEALTH MODE %s", status))
				}
			case "m": // MONITOR DEVICE
				if sel != nil {
					m.selectedMAC = sel.MAC
					m.state = "monitoring"
					return m, nil
				}
			}
		}

	// --- DATA HANDLERS ---

	case ifaceListMsg:
		m.interfaces = msg
		var rows []table.Row
		for _, i := range m.interfaces {
			desc := i.Description
			if len(desc) > 40 { desc = desc[:37] + "..." }
			rows = append(rows, table.Row{desc, i.IP.String(), i.MAC.String()})
		}
		m.ifaceTable.SetRows(rows)
		return m, nil

	case scanResultMsg:
		// FIX DUPLICATION: Using Merge Unique IP
		m.devices = mergeDevicesUniqueIP(m.devices, msg.devices)
		sortDevices(m.devices)
		
		m.scanner = msg.scanner
		m.gatewayIP = m.scanner.MyIP.Mask(net.CIDRMask(24, 32))
		m.gatewayIP[3] = 1
		
		if m.spoofer == nil {
			return m, setupEngineCmd(m.scanner, m.gatewayIP, m.session)
		}
		m.state = "running"
		m.refreshTable()
		return m, nil

case engineReadyMsg:
		if msg.err != nil { m.err = msg.err; return m, nil }
		m.spoofer = msg.spoofer
		m.spoofer6 = msg.spoofer6
		m.forwarder = msg.forwarder
		m.stopChan = msg.stopChan
		
		// [GATEWAY LOCKING]
		m.ifaceIndex = getInterfaceIndex(m.scanner.MyIP)
		if m.ifaceIndex != 0 {
			m.gatewayMAC = m.spoofer.GatewayMAC
			lockGateway(m.ifaceIndex, m.gatewayIP, m.gatewayMAC)
		}

		go m.spoofer.Start()
		go m.spoofer6.Start()
		go m.forwarder.StartForwarding(m.stopChan)
		
		m.state = "running"
		return m, tickCmd()

	case tickMsg:
		if m.state == "running" || m.state == "monitoring" {
			updateSpeedometer(m.session)
			if m.state == "running" {
				m.refreshTable()
			}
			return m, tickCmd()
		}
	}

	if m.state == "iface_select" {
		m.ifaceTable, cmd = m.ifaceTable.Update(msg)
		return m, cmd
	}
	
	if !m.skipTableUpdate { m.table, cmd = m.table.Update(msg) }
	return m, cmd
}

func (m model) View() string {
	if m.err != nil {
		return fmt.Sprintf("\n  ❌ CRITICAL ERROR: %v\n  Press q to quit", m.err)
	}

	var s strings.Builder
	s.WriteString(bannerStyle.Render(banner))
	s.WriteString("\n")

	switch m.state {
	case "iface_select":
		s.WriteString("   " + tealStyle.Render("🔌 SELECT NETWORK INTERFACE") + "\n")
		s.WriteString("   (Choose the active adapter to begin monitoring)\n\n")
		s.WriteString(baseStyle.Render(m.ifaceTable.View()))
		s.WriteString("\n\n" + helpStyle.Render("   [Enter: Select]  [Q: Quit]"))

	case "scanning":
		s.WriteString("   " + goldStyle.Render("🔍 Scanning network... Please wait...") + "\n")

	case "renaming":
		s.WriteString("   " + tealStyle.Render("✏️  RENAME DEVICE") + "\n")
		s.WriteString(fmt.Sprintf("   MAC: %s\n\n", m.selectedMAC))
		s.WriteString("   " + m.textInput.View() + "\n\n")
		s.WriteString(helpStyle.Render("   [Enter: Save]  [Esc: Cancel]"))

	case "monitoring":
		mac := m.selectedMAC.String()
		t := m.session.GetTarget(mac)
		if t == nil {
			s.WriteString("   " + roseStyle.Render("❌ Target not active in session."))
			s.WriteString("\n\n" + helpStyle.Render("   [Esc: Back]"))
			break
		}
		
		var sel *models.Device
		for _, d := range m.devices {
			if d.MAC.String() == mac {
				sel = &d
				break
			}
		}
		
		if sel == nil {
			m.state = "running"
			return m.View()
		}

		t.Mutex.Lock()
		s.WriteString("   " + tealStyle.Render("📊 MONITORING: "+sel.IP.String()) + " (" + sel.Vendor + ")\n\n")
		s.WriteString(fmt.Sprintf("   Speed:   ⬇️ %.1f KB/s | ⬆️ %.1f KB/s\n", t.DisplayDown/1024, t.DisplayUp/1024))
		s.WriteString(fmt.Sprintf("   Traffic: 💻 TCP: %d | ⚡ UDP: %d | 🛡️ ICMP: %d\n", t.TCPCount, t.UDPCount, t.ICMPCount))
		t.Mutex.Unlock()

		s.WriteString("\n   " + roseStyle.Render("   [LIVE TELEMETRY ACTIVE]"))
		s.WriteString("\n\n" + helpStyle.Render("   [Esc: Back to Dashboard]"))

	case "running":
		// Table View
		s.WriteString(baseStyle.Render(m.table.View()))
		s.WriteString("\n\n")

		// Monitoring Section
		var logContent strings.Builder
		stealthStatus := "OFF"
		if m.spoofer != nil && m.spoofer.Stealth { stealthStatus = "ON" }
		
		logContent.WriteString(fmt.Sprintf("   🕵️  STEALTH: %s | ⚡ WORKERS: 8\n", stealthStatus))
		logContent.WriteString("   --------------------------------------\n")
		
		if len(m.logs) == 0 {
			logContent.WriteString("   📡 Waiting for network events...")
		} else {
			for _, l := range m.logs {
				logContent.WriteString("   " + l + "\n")
			}
		}
		
		s.WriteString(logStyle.Render(logContent.String()))
		s.WriteString("\n")

		// Improved Help/Actions
		s.WriteString("   " + helpStyle.Render("Actions: [S] Scan | [R] Rename | [M] Monitor | [B/U] Block/Unblock All | [L] Limit All"))
		s.WriteString("\n   " + helpStyle.Render("Target:  [Enter] Toggle | [Space] Block | []/[]] Limit | [0] Reset | [T] Stealth Toggle"))
	}

	return s.String()
}

// --- HELPER LOGIC ---

// Refresh Table with Cursor Memory
func (m *model) refreshTable() {
	currentCursor := m.table.Cursor()
	var rows []table.Row
	for _, d := range m.devices {
		mac := d.MAC.String()
		name := d.Vendor
		if alias, ok := m.aliases[mac]; ok && alias != "" { name = alias } else if name == "" { name = "Unknown" }
		if d.IP.Equal(m.gatewayIP) { name = "[ROUTER] " + name }
		if d.IP.Equal(m.scanner.MyIP) { name = "[YOU] " + name }

		if len(d.IPv6) > 0 {
			name += " (v6)"
		} else {
			if t := m.session.GetTarget(mac); t != nil && len(t.IPv6) > 0 {
				name += " (v6)"
			}
		}

		downStr, upStr, statusStr := "-", "-", "Idle"

		if t := m.session.GetTarget(mac); t != nil {
			t.Mutex.Lock()
			downStr = fmt.Sprintf("%.1f KB/s", t.DisplayDown/1024.0)
			upStr = fmt.Sprintf("%.1f KB/s", t.DisplayUp/1024.0)
			if t.IsBlocked { statusStr = "⛔ BLOCKED" } else if t.LimitRate > 0 { statusStr = fmt.Sprintf("⚠️ %dK", t.LimitRate/1024) } else { statusStr = "● ACTIVE" }
			t.Mutex.Unlock()
		}
		rows = append(rows, table.Row{d.IP.String(), name, downStr, upStr, statusStr})
	}
	m.table.SetRows(rows)
	if currentCursor < len(rows) { m.table.SetCursor(currentCursor) }
}

// [UPDATED] Helper Logic
func (m *model) activateAllDevices() {
	for _, d := range m.devices {
		if !isSafeDevice(&d, *m) { 
			m.addToSession(&d) // Ini akan otomatis memanggil AttackSingleTarget
		}
	}
}

// [UPDATED] Helper Logic

func (m *model) addToSession(d *models.Device) {
	mac := d.MAC.String()
	// 1. Add to Session Manager
	if m.session.GetTarget(mac) == nil {
		name := m.aliases[mac]
		if name == "" { name = d.Vendor }
		m.session.AddTarget(*d, name)
		m.addLog(fmt.Sprintf("🎯 ADDED TARGET: %s (%s)", d.IP, name))
	}

	// 2. [BURST ATTACK]
	if m.spoofer != nil {
		t := m.session.GetTarget(mac)
		if t != nil {
			go m.spoofer.AttackSingleTarget(t)
		}
	}
}

func (m *model) autoLimit(d *models.Device, delta int) {
	if isSafeDevice(d, *m) { return }
	t := m.session.GetTarget(d.MAC.String())
	if t == nil {
		m.addToSession(d)
		t = m.session.GetTarget(d.MAC.String())
	}
	t.Mutex.Lock()
	newLimit := (t.LimitRate / 1024) + int64(delta)
	if newLimit < 0 { newLimit = 0 }
	if delta == -999999 { newLimit = 0 }
	t.LimitRate = newLimit * 1024
	t.Mutex.Unlock()
	m.refreshTable()
}

func isSafeDevice(d *models.Device, m model) bool {
	return d.IP.Equal(m.gatewayIP) || d.IP.Equal(m.scanner.MyIP)
}

func (m *model) addLog(msg string) {
	m.logs = append(m.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(m.logs) > 5 {
		m.logs = m.logs[1:]
	}
}

// Anti-Duplication with IP Map
func mergeDevicesUniqueIP(old, new []models.Device) []models.Device {
	uniqueMap := make(map[string]models.Device)
	for _, d := range old { uniqueMap[d.IP.String()] = d }
	for _, d := range new { uniqueMap[d.IP.String()] = d }
	var res []models.Device
	for _, d := range uniqueMap { res = append(res, d) }
	return res
}

func updateSpeedometer(sm *models.SessionManager) {
	targets := sm.GetAllTargets()
	now := time.Now()
	for _, t := range targets {
		t.Mutex.Lock()
		currUp := atomic.LoadInt64(&t.BytesUpTotal)
		currDown := atomic.LoadInt64(&t.BytesDownTotal)
		duration := now.Sub(t.LastCheck).Seconds()
		if duration > 0 {
			t.DisplayUp = float64(currUp-t.LastBytesUp) / duration
			t.DisplayDown = float64(currDown-t.LastBytesDown) / duration

			// Push to history
			t.HistoryUp = append(t.HistoryUp, t.DisplayUp)
			if len(t.HistoryUp) > 60 {
				t.HistoryUp = t.HistoryUp[1:]
			}
			t.HistoryDown = append(t.HistoryDown, t.DisplayDown)
			if len(t.HistoryDown) > 60 {
				t.HistoryDown = t.HistoryDown[1:]
			}
		}
		t.LastBytesUp = currUp
		t.LastBytesDown = currDown
		t.LastCheck = now
		t.Mutex.Unlock()
	}
}

func getInterfacesCmd() tea.Msg {
	ifaces, err := core.GetAvailableInterfaces()
	if err != nil { return err }
	return ifaceListMsg(ifaces)
}

func scanNetworkCmd(iface core.NetworkInterface) tea.Cmd {
	return func() tea.Msg {
		scanner, err := core.NewScanner(iface)
		if err != nil { return err }
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		devices, err := scanner.Scan(ctx)
		if err != nil { return err }
		return scanResultMsg{devices: devices, scanner: scanner}
	}
}

func setupEngineCmd(scanner *core.Scanner, gwIP net.IP, session *models.SessionManager) tea.Cmd {
	return func() tea.Msg {
		gwMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} 
		
		// 1. Setup IPv4 Spoofer
		spoofer := core.NewSpoofer(scanner.InterfaceName, scanner.MyMAC, scanner.MyIP, gwIP, gwMAC, session)
		
		// 2. Setup Handle
		fHandle, err := pcap.OpenLive(scanner.InterfaceName, 1048576, true, pcap.BlockForever)
		if err != nil { return engineReadyMsg{err: err} }

		// 3. Setup IPv6 Spoofer
		spoofer6 := core.NewSpoofer6(fHandle, scanner.MyMAC, session)
		
		// --- LAN FIX CONFIG ---
		myIP := scanner.MyIP.String()
		// Filter BPF
		filter := fmt.Sprintf("arp or icmp6 or (ip and not dst host %s)", myIP)
		fHandle.SetBPFFilter(filter)
		
		forwarder := core.NewForwarder(fHandle, scanner.MyMAC, gwMAC, session)
		stopChan := make(chan struct{})
		
		return engineReadyMsg{
			spoofer:   spoofer, 
			spoofer6:  spoofer6,
			forwarder: forwarder, 
			stopChan:  stopChan,
		}
	}
}

func tickCmd() tea.Cmd { return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) }) }

func sortDevices(d []models.Device) {
	sort.Slice(d, func(i, j int) bool {
		// Sort by IP End Byte
		ip1 := d[i].IP.To4()
		ip2 := d[j].IP.To4()
		if ip1 != nil && ip2 != nil {
			return ip1[3] < ip2[3]
		}
		return d[i].IP.String() < d[j].IP.String()
	})
}

func (m *model) getSelectedDevice() *models.Device {
	row := m.table.SelectedRow()
	if len(row) == 0 { return nil }
	targetIP := net.ParseIP(row[0])
	for _, d := range m.devices { if d.IP.Equal(targetIP) { return &d } }
	return nil
}

func getInterfaceIndex(myIP net.IP) int {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs { if strings.Contains(addr.String(), myIP.String()) { return i.Index } }
	}
	return 0
}

func lockGateway(idx int, ip net.IP, mac net.HardwareAddr) {
	if mac == nil { return }
	macStr := strings.ReplaceAll(mac.String(), ":", "-")
	exec.Command("netsh", "interface", "ip", "add", "neighbors", strconv.Itoa(idx), ip.String(), macStr).Run()
}

func unlockGateway(idx int, ip net.IP) {
	exec.Command("netsh", "interface", "ip", "delete", "neighbors", strconv.Itoa(idx), ip.String()).Run()
}

func (m *model) cleanup() {
	if m.stopChan != nil { close(m.stopChan) }
	if m.ifaceIndex != 0 { unlockGateway(m.ifaceIndex, m.gatewayIP) }
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\n 🛑 FLOWGUARD STOPPED. Network restored.")
}