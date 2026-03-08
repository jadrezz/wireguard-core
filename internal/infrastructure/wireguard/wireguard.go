package wireguard

import (
	"encoding/base64"
	"net"
	"time"

	"wireguard-core/internal/domain"
	wgconfig "wireguard-core/internal/infrastructure/wireguard/config"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgPeerConfig struct {
	endpoint                    net.UDPAddr
	persistentKeepaliveInterval time.Duration
}

type WgManager struct {
	client     *wgctrl.Client
	peerCfg    WgPeerConfig
	defaultDNS []string
}

var _ domain.WireGuardManager = (*WgManager)(nil)

func mapPeer(p wgtypes.Peer) domain.Peer {
	return domain.Peer{
		PublicKey:     p.PublicKey.String(),
		AllowedIPs:    p.AllowedIPs,
		Endpoint:      p.Endpoint,
		TransmitBytes: p.TransmitBytes,
		ReceiveBytes:  p.ReceiveBytes,
		LastHandshake: p.LastHandshakeTime,
	}
}

func (w *WgManager) GetAllDevices() ([]domain.Device, error) {
	devices, err := w.client.Devices()
	if err != nil {
		return nil, err
	}

	result := make([]domain.Device, 0, len(devices))
	for _, d := range devices {
		peers := make([]domain.Peer, 0, len(d.Peers))
		for _, p := range d.Peers {
			peers = append(peers, mapPeer(p))
		}
		result = append(result, domain.Device{
			Name:  d.Name,
			Peers: peers,
		})
	}

	return result, nil
}

func (w *WgManager) GetDevicePeers(deviceName string) ([]domain.Peer, error) {
	device, err := w.client.Device(deviceName)
	if err != nil {
		return nil, domain.ErrDevice
	}

	peers := make([]domain.Peer, 0, len(device.Peers))
	for _, p := range device.Peers {
		peers = append(peers, mapPeer(p))
	}

	return peers, nil
}

func (w *WgManager) CreatePeer(deviceName string, peerAllowedIPs []net.IPNet, dns []string) (string, error) {
	device, err := w.client.Device(deviceName)
	if err != nil {
		return "", domain.ErrDevice
	}

	privatePeerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	publicPeerKey := privatePeerKey.PublicKey()

	peerIP, err := findFreeAddr(device)
	if err != nil {
		return "", err
	}

	peerServerCfg := wgtypes.PeerConfig{
		PublicKey:                   publicPeerKey,
		Endpoint:                    &w.peerCfg.endpoint,
		PersistentKeepaliveInterval: &w.peerCfg.persistentKeepaliveInterval,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  []net.IPNet{peerIP},
	}

	deviceCfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peerServerCfg},
	}

	if err = w.client.ConfigureDevice(device.Name, deviceCfg); err != nil {
		return "", domain.ErrDevice
	}

	if len(dns) == 0 {
		dns = w.defaultDNS
	}

	clientCfg := wgconfig.ClientConfig{
		PrivateKey:          privatePeerKey.String(),
		Address:             peerIP.String(),
		ServerPublicKey:     device.PublicKey.String(),
		Endpoint:            w.peerCfg.endpoint.IP,
		Port:                device.ListenPort,
		PersistentKeepalive: int(w.peerCfg.persistentKeepaliveInterval.Seconds()),
		AllowedIPs:          peerAllowedIPs,
		DNS:                 dns,
	}

	return wgconfig.RenderClientConfig(clientCfg)
}

func (w *WgManager) RemovePeer(deviceName string, publicKey string) error {
	device, err := w.client.Device(deviceName)
	if err != nil {
		return domain.ErrDevice
	}

	keyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return domain.ErrInvalidKey
	}

	peerKey, err := wgtypes.NewKey(keyBytes)
	if err != nil {
		return domain.ErrInvalidKey
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: peerKey,
		Remove:    true,
	}
	deviceCfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peerCfg},
	}

	if err = w.client.ConfigureDevice(device.Name, deviceCfg); err != nil {
		return domain.ErrDevice
	}

	return nil
}

func (w *WgManager) CountFreeAddrs(deviceName string) (int, error) {
	device, err := w.client.Device(deviceName)
	if err != nil {
		return 0, domain.ErrDevice
	}

	return countFreeAddrs(device)
}

func (w *WgManager) HealthCheck() error {
	_, err := w.client.Devices()
	return err
}

func (w *WgManager) Close() error {
	return w.client.Close()
}

func NewWgManager(client *wgctrl.Client, peerCfg WgPeerConfig, defaultDNS []string) *WgManager {
	return &WgManager{
		client:     client,
		peerCfg:    peerCfg,
		defaultDNS: defaultDNS,
	}
}

func NewWgPeerConfig(endpoint net.UDPAddr, persistentKeepaliveInterval time.Duration) WgPeerConfig {
	return WgPeerConfig{
		endpoint:                    endpoint,
		persistentKeepaliveInterval: persistentKeepaliveInterval,
	}
}
