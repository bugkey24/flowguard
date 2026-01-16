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
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			Width(60).
			Align(lipgloss.Center)

	inputBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#FFD700")).
			Padding(1, 2).
			Width(50)
)

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
}

// Messages
type ifaceListMsg []core.NetworkInterface
type scanResultMsg struct {
	devices []models.Device
	scanner *core.Scanner
}
type engineReadyMsg struct {
	spoofer   *core.Spoofer
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

		// --- SCREEN 2: RENAME ---
		if m.state == "renaming" {
			switch msg.Type {
			case tea.KeyEnter:
				utils.SaveAlias(m.selectedMAC.String(), m.textInput.Value())
				m.aliases, _ = utils.LoadAliases()
				m.state = "running"
				m.refreshTable()
				return m, nil
			case tea.KeyEsc:
				m.state = "running"
				m.textInput.Blur()
				return m, nil
			}
			m.textInput, cmd = m.textInput.Update(msg)
			return m, cmd
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
					t.Mutex.Unlock()
					m.refreshTable()
				}
			case "]": if sel != nil { m.autoLimit(sel, 50) }
			case "[": if sel != nil { m.autoLimit(sel, -50) }
			case "0": if sel != nil { m.autoLimit(sel, -999999) }
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
		m.spoofer, m.forwarder, m.stopChan = msg.spoofer, msg.forwarder, msg.stopChan
		
		// [GATEWAY LOCKING]
		m.ifaceIndex = getInterfaceIndex(m.scanner.MyIP)
		if m.ifaceIndex != 0 {
			m.gatewayMAC = m.spoofer.GatewayMAC
			lockGateway(m.ifaceIndex, m.gatewayIP, m.gatewayMAC)
		}

		go m.spoofer.Start()
		go m.forwarder.StartForwarding(m.stopChan)
		m.state = "running"
		return m, tickCmd()

	case tickMsg:
		if m.state == "running" {
			updateSpeedometer(m.session)
			m.refreshTable()
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
	s := "\n" + headerStyle.Render("FLOWGUARD PRO - NETWORK CONTROLLER") + "\n\n"
	if m.err != nil { return fmt.Sprintf("CRITICAL ERROR: %v\nPress q to quit", m.err) }

	switch m.state {
	case "iface_select":
		s += " 🔌 SELECT NETWORK INTERFACE:\n"
		s += " (Select the active LAN or WiFi Adapter)\n\n"
		s += baseStyle.Render(m.ifaceTable.View()) + "\n\n"
		s += " [UP/DOWN: Select] [ENTER: Select] [Q: Quit]"

	case "scanning":
		s += " 🔍 Scanning network... Please wait.\n"
		
	case "renaming":
		s += " ✏️  RENAME DEVICE:\n" + fmt.Sprintf("    MAC: %s\n\n", m.selectedMAC)
		s += inputBoxStyle.Render(m.textInput.View()) + "\n\n [Enter: Save] [Esc: Cancel]"
		
	case "running":
		s += baseStyle.Render(m.table.View()) + "\n\n"
		s += " [ENTER]: Toggle Active | [S]: Rescan | [R]: Rename\n"
		s += " Global: [B]: Block ALL | [U]: Unblock ALL | [L]: Limit ALL (50K)\n"
		s += " Target: [SPACE]: Block | [ ] ]: +Limit | [ [ ]: -Limit | [0]: Reset"
	}
	return s
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

func (m *model) activateAllDevices() {
	for _, d := range m.devices {
		if !isSafeDevice(&d, *m) { m.addToSession(&d) }
	}
}

func (m *model) addToSession(d *models.Device) {
	mac := d.MAC.String()
	if m.session.GetTarget(mac) == nil {
		name := m.aliases[mac]
		if name == "" { name = d.Vendor }
		m.session.AddTarget(*d, name)
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
			t.DisplayUp = float64(currUp - t.LastBytesUp) / duration
			t.DisplayDown = float64(currDown - t.LastBytesDown) / duration
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
		spoofer := core.NewSpoofer(scanner.InterfaceName, scanner.MyMAC, scanner.MyIP, gwIP, gwMAC, session)
		fHandle, err := pcap.OpenLive(scanner.InterfaceName, 65536, true, pcap.BlockForever)
		if err != nil { return engineReadyMsg{err: err} }
		// BPF Simple
		fHandle.SetBPFFilter("ip") 
		forwarder := core.NewForwarder(fHandle, scanner.MyMAC, gwMAC, session)
		stopChan := make(chan struct{})
		return engineReadyMsg{spoofer: spoofer, forwarder: forwarder, stopChan: stopChan}
	}
}

func tickCmd() tea.Cmd { return tea.Tick(1*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

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
	if m.state != "running" { return nil }
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
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\n 🛑 FLOWGUARD STOPPED. Network restored.")
}