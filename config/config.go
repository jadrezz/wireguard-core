package config

import (
	"fmt"
	"net"
	"time"

	"wireguard-core/internal/infrastructure/wireguard"

	"github.com/caarlos0/env/v11"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type AppConfig struct {
	Endpoint      string        `env:"WG_ENDPOINT,required"`
	Port          int           `env:"WG_PORT,required"`
	KeepAlive     time.Duration `env:"WG_KEEP_ALIVE,required"` // e.g. "25s", "1m"
	DefaultDNS    []string      `env:"WG_DEFAULT_DNS" envDefault:"8.8.8.8"`
	ConfigDir     string        `env:"WG_CONFIG_DIR" envDefault:"/etc/wireguard"`
	ExternalIface string        `env:"WG_EXTERNAL_IFACE" envDefault:"eth0"`
}

type WireGuardSetup struct {
	Manager       *wireguard.WgManager
	Persister     *wireguard.ConfigPersister
	ServerManager *wireguard.WgServerManager
	DisabledStore *wireguard.DisabledPeerFileStore
	Firewall      *wireguard.IptablesRunner
}

func InitWireGuard() (*WireGuardSetup, error) {
	cfg, err := env.ParseAs[AppConfig]()
	if err != nil {
		return nil, err
	}

	if err := Preflight(cfg.ConfigDir); err != nil {
		return nil, err
	}

	ip := net.ParseIP(cfg.Endpoint)
	if ip == nil {
		return nil, fmt.Errorf("invalid WG_ENDPOINT IP address: %s", cfg.Endpoint)
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	endpoint := net.UDPAddr{
		IP:   ip,
		Port: cfg.Port,
	}

	peerCfg := wireguard.NewWgPeerConfig(endpoint, cfg.KeepAlive)
	disabledStore := wireguard.NewDisabledPeerFileStore(cfg.ConfigDir)
	firewall := wireguard.NewIptablesRunner()

	return &WireGuardSetup{
		Manager:       wireguard.NewWgManager(client, peerCfg, cfg.DefaultDNS),
		Persister:     wireguard.NewConfigPersister(client, cfg.ConfigDir, cfg.ExternalIface, disabledStore),
		ServerManager: wireguard.NewServerManager(cfg.ConfigDir, cfg.ExternalIface),
		DisabledStore: disabledStore,
		Firewall:      firewall,
	}, nil
}
