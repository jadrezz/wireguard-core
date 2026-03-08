package domain

import "net"

type WireGuardManager interface {
	GetAllDevices() ([]Device, error)
	GetDevicePeers(deviceName string) ([]Peer, error)
	CreatePeer(deviceName string, peerAllowedIPs []net.IPNet, dns []string) (string, error)
	RemovePeer(deviceName string, publicKey string) error
	CountFreeAddrs(deviceName string) (int, error)
	HealthCheck() error
	Close() error
}

type ConfigPersister interface {
	SyncConfig(deviceName string) error
}

type ServerManager interface {
	InitServer(params ServerInitParams) error
	ResetServer(deviceName string) error
}

type DisabledPeerStore interface {
	Add(deviceName, publicKey string) error
	Remove(deviceName, publicKey string) error
	List(deviceName string) ([]string, error)
	Contains(deviceName, publicKey string) (bool, error)
}

type Firewall interface {
	InsertForwardDrop(iface, peerCIDR string) error
	RemoveForwardDrop(iface, peerCIDR string) error
}
