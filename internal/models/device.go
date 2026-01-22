package models

import (
	"net"
)

type Device struct {
	IP     net.IP
	IPv6   net.IP
	MAC    net.HardwareAddr
	Vendor string
}