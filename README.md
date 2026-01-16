# FlowGuard Pro 🛡️

**FlowGuard Pro** is a terminal-based Network Traffic Controller built with Go (Golang). Inspired by tools like _NetCut_ and _SelfishNet_, it allows you to monitor network devices, manage bandwidth, and block internet access for specific targets on your local network using ARP Spoofing techniques.

> ⚠️ **DISCLAIMER:** This tool is for **EDUCATIONAL and TESTING PURPOSES ONLY**. Using this tool on networks without permission is illegal. The author is not responsible for any misuse.

## 🚀 Features

- **🔍 Network Scanning:** Fast & aggressive device discovery (LAN/WiFi).
- **🛡️ Gateway Locking:** Uses `netsh` to prevent the attacker's own internet from cutting off.
- **⚡ Reactive Spoofing:** Aggressive ARP spoofing engine to maintain control over modern routers.
- **📉 Bandwidth Limiter:** Limit upload/download speeds for specific devices.
- **🚫 Internet Blocker:** Cut off internet connection for selected targets.
- **📊 Real-time Monitoring:** Live speedometer (Upload/Download) for tracked targets.
- **🎮 TUI Interface:** Beautiful terminal UI powered by `bubbletea`.

## 📋 Requirements

- **OS:** Windows 10/11 (Required for `netsh` & `npcap`).
- **Library:** [Npcap](https://npcap.com/) (Must be installed with "WinPcap API-compatible mode").
- **Go:** Version 1.19+.

## 📦 Installation

1.  Clone the repository:

    ```bash
    git clone [https://github.com/bugkey24/flowguard.git](https://github.com/bugkey24/flowguard.git)
    cd flowguard
    ```

2.  Install dependencies:

    ```bash
    go mod tidy
    ```

3.  **Run as Administrator** (Crucial for packet injection & gateway locking):
    ```bash
    go run main.go
    ```

## 🎮 Controls

| Key                | Action                                |
| :----------------- | :------------------------------------ |
| **Start Screen**   |                                       |
| `↑` / `↓`          | Select Network Interface              |
| `Enter`            | Confirm Interface & Start Scan        |
| **Main Dashboard** |                                       |
| `↑` / `↓`          | Navigate Device List                  |
| `Enter`            | **Toggle Attack** (Add/Remove Target) |
| `Space`            | **Block/Unblock** Selected Target     |
| `]`                | Increase Limit (+50KB/s)              |
| `[`                | Decrease Limit (-50KB/s)              |
| `0`                | Reset Limit (Unlimited)               |
| `B`                | **Block ALL** Active Targets          |
| `U`                | **Unblock ALL** Active Targets        |
| `L`                | **Limit ALL** Active Targets (50KB/s) |
| `S`                | Rescan Network                        |
| `R`                | Rename Device (Alias)                 |
| `Q`                | Quit & Restore Network                |

## 🛠️ Known Issues (Beta)

- Some highly secure routers with "Dynamic ARP Inspection" might resist the spoofing.
- Block/Limit features might fluctuate on unstable WiFi connections.

## 📄 License

MIT License. See [LICENSE](LICENSE) file for details.
