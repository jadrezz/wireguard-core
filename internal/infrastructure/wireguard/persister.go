package wireguard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"wireguard-core/internal/domain"
	wgconfig "wireguard-core/internal/infrastructure/wireguard/config"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func formatAllowedIPs(ips []net.IPNet) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

type ConfigPersister struct {
	client        *wgctrl.Client
	configDir     string
	externalIface string
	disabledStore domain.DisabledPeerStore
}

var _ domain.ConfigPersister = (*ConfigPersister)(nil)

func NewConfigPersister(client *wgctrl.Client, configDir, externalIface string, disabledStore domain.DisabledPeerStore) *ConfigPersister {
	return &ConfigPersister{
		client:        client,
		configDir:     configDir,
		externalIface: externalIface,
		disabledStore: disabledStore,
	}
}

func (p *ConfigPersister) SyncConfig(deviceName string) error {
	device, err := p.client.Device(deviceName)
	if err != nil {
		return err
	}

	wgAddr, err := getWgAddr(deviceName)
	if err != nil {
		return err
	}

	peers := make([]wgconfig.ServerPeerConfig, 0, len(device.Peers))
	for _, peer := range device.Peers {
		peers = append(peers, wgconfig.ServerPeerConfig{
			PublicKey:  peer.PublicKey.String(),
			AllowedIPs: formatAllowedIPs(peer.AllowedIPs),
		})
	}

	ones, _ := wgAddr.Mask.Size()
	networkIP := wgAddr.IP.Mask(wgAddr.Mask)
	subnet := (&net.IPNet{IP: networkIP, Mask: wgAddr.Mask}).String()

	disabledIPs := make([]string, 0)
	if p.disabledStore != nil {
		disabledKeys, err := p.disabledStore.List(deviceName)
		if err != nil {
			return err
		}
		keySet := make(map[string]struct{})
		for _, k := range disabledKeys {
			keySet[k] = struct{}{}
		}
		for _, peer := range device.Peers {
			if _, ok := keySet[peer.PublicKey.String()]; ok && len(peer.AllowedIPs) > 0 {
				disabledIPs = append(disabledIPs, peer.AllowedIPs[0].String())
			}
		}
	}

	cfg := wgconfig.ServerConfig{
		PrivateKey:      device.PrivateKey.String(),
		Address:         fmt.Sprintf("%s/%d", wgAddr.IP.String(), ones),
		ListenPort:      device.ListenPort,
		Subnet:          subnet,
		ExternalIface:   p.externalIface,
		Peers:           peers,
		DisabledPeerIPs: disabledIPs,
	}

	rendered, err := wgconfig.RenderServerConfig(cfg)
	if err != nil {
		return err
	}

	configPath := filepath.Join(p.configDir, deviceName+".conf")
	return os.WriteFile(configPath, []byte(rendered), 0600)
}
