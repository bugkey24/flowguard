package models

import (
	"net"
)

type Device struct {
	IP     net.IP
	MAC    net.HardwareAddr
	Vendor string
}