package wireguard

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"wireguard-core/internal/domain"
	wgconfig "wireguard-core/internal/infrastructure/wireguard/config"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgServerManager struct {
	configDir     string
	externalIface string
}

var _ domain.ServerManager = (*WgServerManager)(nil)

func NewServerManager(configDir, externalIface string) *WgServerManager {
	return &WgServerManager{
		configDir:     configDir,
		externalIface: externalIface,
	}
}

func (m *WgServerManager) InitServer(params domain.ServerInitParams) error {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(params.Address)
	if err != nil {
		return err
	}

	cfg := wgconfig.ServerConfig{
		PrivateKey:    privateKey.String(),
		Address:       params.Address,
		ListenPort:    params.ListenPort,
		Subnet:        ipnet.String(),
		ExternalIface: m.externalIface,
		Peers:         nil,
	}

	rendered, err := wgconfig.RenderServerConfig(cfg)
	if err != nil {
		return err
	}

	configPath := filepath.Join(m.configDir, params.DeviceName+".conf")
	if err := os.WriteFile(configPath, []byte(rendered), 0600); err != nil {
		return err
	}

	return exec.Command("wg-quick", "up", params.DeviceName).Run()
}

func (m *WgServerManager) ResetServer(deviceName string) error {
	_ = exec.Command("wg-quick", "down", deviceName).Run()

	configPath := filepath.Join(m.configDir, deviceName+".conf")
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	disabledPath := filepath.Join(m.configDir, deviceName+disabledPeersSuffix)
	_ = os.Remove(disabledPath)

	return nil
}
