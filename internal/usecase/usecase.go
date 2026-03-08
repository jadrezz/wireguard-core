package usecase

import (
	"log/slog"
	"net"
	"sync"

	"wireguard-core/internal/domain"
)

type WireGuardManagerService interface {
	GetAllDevices() ([]domain.Device, error)
	GetDevicePeers(deviceName string) ([]domain.Peer, error)
	GetPeer(deviceName string, publicKey string) (domain.Peer, error)
	CreatePeer(deviceName string, peerAllowedIPs []net.IPNet, dns []string) (string, error)
	RemovePeer(deviceName string, publicKey string) error
	DisablePeer(deviceName string, publicKey string) error
	EnablePeer(deviceName string, publicKey string) error
	CountFreeAddrs(deviceName string) (int, error)
	HealthCheck() error
	InitServer(params domain.ServerInitParams) error
	ResetServer(deviceName string) error
}

type WireGuardService struct {
	wgManager     domain.WireGuardManager
	persister     domain.ConfigPersister
	serverMgr     domain.ServerManager
	disabledStore domain.DisabledPeerStore
	firewall      domain.Firewall
	logger        *slog.Logger
	mu            sync.Mutex
}

func NewWireGuardService(
	wgManager domain.WireGuardManager,
	persister domain.ConfigPersister,
	serverMgr domain.ServerManager,
	disabledStore domain.DisabledPeerStore,
	firewall domain.Firewall,
	logger *slog.Logger,
) *WireGuardService {
	return &WireGuardService{
		wgManager:     wgManager,
		persister:     persister,
		serverMgr:     serverMgr,
		disabledStore: disabledStore,
		firewall:      firewall,
		logger:        logger,
	}
}

func (s *WireGuardService) GetAllDevices() ([]domain.Device, error) {
	return s.wgManager.GetAllDevices()
}

func (s *WireGuardService) GetDevicePeers(deviceName string) ([]domain.Peer, error) {
	return s.wgManager.GetDevicePeers(deviceName)
}

func (s *WireGuardService) GetPeer(deviceName string, publicKey string) (domain.Peer, error) {
	peers, err := s.wgManager.GetDevicePeers(deviceName)
	if err != nil {
		return domain.Peer{}, err
	}
	return findPeerByPublicKey(peers, publicKey)
}

func (s *WireGuardService) CreatePeer(deviceName string, peerAllowedIPs []net.IPNet, dns []string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.wgManager.CreatePeer(deviceName, peerAllowedIPs, dns)
	if err != nil {
		return "", err
	}

	if s.persister != nil {
		if syncErr := s.persister.SyncConfig(deviceName); syncErr != nil {
			s.logger.Warn("failed to sync config after creating peer", "device", deviceName, "error", syncErr)
		}
	}

	return cfg, nil
}

func (s *WireGuardService) RemovePeer(deviceName string, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.wgManager.RemovePeer(deviceName, publicKey); err != nil {
		return err
	}

	if s.persister != nil {
		if syncErr := s.persister.SyncConfig(deviceName); syncErr != nil {
			s.logger.Warn("failed to sync config after removing peer", "device", deviceName, "error", syncErr)
		}
	}

	return nil
}

func (s *WireGuardService) DisablePeer(deviceName string, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	peers, err := s.wgManager.GetDevicePeers(deviceName)
	if err != nil {
		return err
	}
	cidr, err := peerTunnelCIDR(peers, publicKey)
	if err != nil {
		return err
	}

	if err := s.disabledStore.Add(deviceName, publicKey); err != nil {
		return err
	}
	if s.firewall != nil {
		if err := s.firewall.InsertForwardDrop(deviceName, cidr); err != nil {
			_ = s.disabledStore.Remove(deviceName, publicKey)
			return err
		}
	}
	if s.persister != nil {
		if syncErr := s.persister.SyncConfig(deviceName); syncErr != nil {
			s.logger.Warn("failed to sync config after disabling peer", "device", deviceName, "error", syncErr)
		}
	}
	return nil
}

func (s *WireGuardService) EnablePeer(deviceName string, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ok, err := s.disabledStore.Contains(deviceName, publicKey)
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrPeerNotDisabled
	}

	peers, err := s.wgManager.GetDevicePeers(deviceName)
	if err != nil {
		return err
	}
	cidr, err := peerTunnelCIDR(peers, publicKey)
	if err != nil {
		return err
	}

	if err := s.disabledStore.Remove(deviceName, publicKey); err != nil {
		return err
	}
	if s.firewall != nil {
		_ = s.firewall.RemoveForwardDrop(deviceName, cidr)
	}
	if s.persister != nil {
		if syncErr := s.persister.SyncConfig(deviceName); syncErr != nil {
			s.logger.Warn("failed to sync config after enabling peer", "device", deviceName, "error", syncErr)
		}
	}
	return nil
}

func findPeerByPublicKey(peers []domain.Peer, publicKey string) (domain.Peer, error) {
	for _, p := range peers {
		if p.PublicKey == publicKey {
			return p, nil
		}
	}
	return domain.Peer{}, domain.ErrPeerNotFound
}

func peerTunnelCIDR(peers []domain.Peer, publicKey string) (string, error) {
	peer, err := findPeerByPublicKey(peers, publicKey)
	if err != nil {
		return "", err
	}
	if len(peer.AllowedIPs) == 0 {
		return "", domain.ErrPeerNotFound
	}
	return peer.AllowedIPs[0].String(), nil
}

func (s *WireGuardService) CountFreeAddrs(deviceName string) (int, error) {
	return s.wgManager.CountFreeAddrs(deviceName)
}

func (s *WireGuardService) HealthCheck() error {
	return s.wgManager.HealthCheck()
}

func (s *WireGuardService) InitServer(params domain.ServerInitParams) error {
	if s.serverMgr == nil {
		return domain.ErrServerManagement
	}
	return s.serverMgr.InitServer(params)
}

func (s *WireGuardService) ResetServer(deviceName string) error {
	if s.serverMgr == nil {
		return domain.ErrServerManagement
	}
	return s.serverMgr.ResetServer(deviceName)
}
