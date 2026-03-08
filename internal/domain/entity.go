package domain

import (
	"net"
	"time"
)

type Device struct {
	Name  string
	Peers []Peer
}

type Peer struct {
	PublicKey     string
	AllowedIPs    []net.IPNet
	Endpoint      *net.UDPAddr
	TransmitBytes int64
	ReceiveBytes  int64
	LastHandshake time.Time
}

type ServerInitParams struct {
	DeviceName string
	Address    string
	ListenPort int
}
