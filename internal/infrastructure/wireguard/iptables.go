package wireguard

import (
	"os/exec"

	"wireguard-core/internal/domain"
)

type IptablesRunner struct{}

var _ domain.Firewall = (*IptablesRunner)(nil)

func NewIptablesRunner() *IptablesRunner {
	return &IptablesRunner{}
}

func (r *IptablesRunner) InsertForwardDrop(iface, peerCIDR string) error {
	cmd := exec.Command("iptables", "-I", "FORWARD", "1", "-i", iface, "-s", peerCIDR, "-j", "DROP")
	return cmd.Run()
}

func (r *IptablesRunner) RemoveForwardDrop(iface, peerCIDR string) error {
	cmd := exec.Command("iptables", "-D", "FORWARD", "-i", iface, "-s", peerCIDR, "-j", "DROP")
	return cmd.Run()
}
