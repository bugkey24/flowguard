# FlowGuard Pro

![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-gray?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)

**FlowGuard Pro** is an advanced, terminal-based Network Traffic Controller built with Go (Golang). It is designed to give you complete visibility and control over your Local Area Network (LAN).

Inspired by legendary tools like _NetCut_ and _SelfishNet_, FlowGuard Pro modernizes the concept by introducing **Dual-Stack Support (IPv4 & IPv6)**, cross-platform compatibility, and a beautiful TUI (Terminal User Interface).

> ⚠️ **LEGAL DISCLAIMER**
>
> _This tool is developed for **EDUCATIONAL, RESEARCH, and NETWORK ADMINISTRATION PURPOSES ONLY**._
> _Using this tool against networks or devices without explicit permission from the owner is **ILLEGAL** and may violate local and international laws. The author assumes no liability for misuse._

---

## Key Features

### Dual-Stack Network Control

- **IPv4 Dominance:** Uses aggressive **ARP Spoofing** to redirect traffic through your machine (MITM).
- **IPv6 Neutralization (New):** Uses **ICMPv6 Neighbor Advertisement Spoofing (DAD Attack)** to force targets to drop their IPv6 connections, preventing them from bypassing blocks via modern protocols.

### High-Performance Engine

- **Burst Mode:** Instantly cuts off connections by sending a barrage of spoofed packets when a target is blocked (eliminates the "second block failure" bug).
- **LAN Optimization:** Smart BPF Filtering prevents packet loopbacks and CPU saturation, ensuring the attacker's internet remains stable even on Gigabit Ethernet connections.

### Self-Protection

- **Gateway Locking:** Automatically locks the Gateway's MAC address in your system's ARP table (`netsh` on Windows, `ip neigh` on Linux) to prevent self-poisoning.

### Real-Time Management

- **Live Speedometer:** Monitor real-time Upload/Download speeds of any target.
- **Bandwidth Limiter:** Throttle connection speeds (e.g., limit a device to 50KB/s).
- **Device Alias:** Rename devices (e.g., "My Phone", "Office PC") with persistent saving.

---

## Requirements

### Windows

- **OS:** Windows 10 / 11.
- **Driver:** [Npcap](https://npcap.com/) (Install with **"Install Npcap in WinPcap API-compatible Mode"** checked).
- **Privileges:** Must run as Administrator.

### Linux (Debian/Ubuntu/Alpine)

- **Library:** `libpcap-dev`.
- **Privileges:** Must run with `sudo`.

---

## Installation & Usage

### 1. Clone Repository

```bash
git clone [https://github.com/bugkey24/flowguard.git](https://github.com/bugkey24/flowguard.git)
cd flowguard
```

### 2. Install Dependencies

```Bash
go mod tidy
```

### 3. Run the Application

**Windows (PowerShell/CMD as Admin):**

```PowerShell
go run main.go
```

**Linux (Terminal):**

```Bash

# Install libpcap first (Debian/Ubuntu)
sudo apt update && sudo apt install libpcap-dev

# Run FlowGuard
sudo go run main.go
```

---

### Controls & Shortcuts

**The interface is navigable entirely via keyboard.**

| Key              | Context        | Action                                   |
| ---------------- | -------------- | ---------------------------------------- |
| **Start Screen** |                |                                          |
| ↑ / ↓            | Interface List | Select Network Interface (WiFi/Ethernet) |
| Enter            | Interface List | Confirm Interface & Start Scanning       |
| **Dashboard**    |                |                                          |
| ↑ / ↓            | Device List    | Navigate through devices                 |
| Enter            | Device List    | Toggle Active (Monitor target traffic)   |
| Space            | Device List    | Block / Unblock Internet Access          |
| R                | Device List    | Rename Device (Set Alias)                |
| S                | Global         | Rescan Network for new devices           |
| J                | Limiter        | Increase Limit (+50 KB/s)                |
| [                | Limiter        | Decrease Limit (-50 KB/s)                |
| ]                | Limiter        | Reset Limit (Unlimited)                  |
| B                | Global Action  | Block ALL Active Targets                 |
| U                | Global Action  | Unblock ALL Targets                      |
| L                | Global Action  | Limit ALL Active Targets (50 KB/s)       |
| Q / Ctrl+C       | Global         | Quit & Restore Network                   |

---

# Technical Details

FlowGuard Pro operates at **Layer 2 (Data Link)** and **Layer 3 (Network)** of the OSI Model.

1. **Scanner:** Uses `pcap` to listen for ARP traffic and passively inspects IPv6 packets to discover dual-stack devices.
2. **IPv4 Attack (ARP):** Continually sends forged ARP replies to the Target (saying "I am the Router") and the Router (saying "I am the Target").

3. **IPv6 Attack (ICMPv6):** Sends forged **Neighbor Advertisements** claiming that the Target's IPv6 address belongs to the Attacker's MAC. This triggers a "Duplicate Address Detection" (DAD) conflict, causing the target OS to disable IPv6 or drop the connection.
4. **Forwarding Engine:**
   - Only forwards packets belonging to tracked targets.
   - Applies Token Bucket algorithms for Bandwidth Limiting.
   - Drops packets instantly if "Block" is active.

---

Troubleshooting

1. **"Internet on my laptop (Attacker) dies when using LAN!"** FlowGuard uses strict BPF filters (`not dst host [MyIP]`) to prevent your own high-speed download traffic from clogging the packet capture engine. Ensure you are using the latest version of the code.

2. **"Target is not blocked on YouTube/Netflix."** Ensure the target shows (v6) next to its name. If not, wait a few seconds for FlowGuard to detect the IPv6 address. FlowGuard automatically attacks both protocols to ensure total blockage.

3. **"I don't see any devices."**
   - Windows: Ensure you selected the correct Network Adapter (check IP address).
   - Linux: Ensure you are running with `sudo`.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
   Open a Pull Request

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
