package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"

	"wireguard-core/internal/domain"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

type subnetInfo struct {
	network   uint32
	broadcast uint32
	used      map[uint32]bool
}

func getSubnetInfo(device *wgtypes.Device) (subnetInfo, error) {
	wgIPnet, err := getWgAddr(device.Name)
	if err != nil {
		return subnetInfo{}, err
	}

	used := make(map[uint32]bool, len(device.Peers)+1)
	used[ipToUint32(wgIPnet.IP)] = true
	for _, peer := range device.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			if v4 := allowedIP.IP.To4(); v4 != nil {
				used[ipToUint32(v4)] = true
			}
		}
	}

	mask := binary.BigEndian.Uint32(wgIPnet.Mask)
	network := ipToUint32(wgIPnet.IP) & mask
	broadcast := network | ^mask

	return subnetInfo{
		network:   network,
		broadcast: broadcast,
		used:      used,
	}, nil
}

func findFreeAddr(device *wgtypes.Device) (net.IPNet, error) {
	info, err := getSubnetInfo(device)
	if err != nil {
		return net.IPNet{}, err
	}

	for addr := info.network + 1; addr < info.broadcast; addr++ {
		if !info.used[addr] {
			return net.IPNet{
				IP:   uint32ToIP(addr),
				Mask: net.CIDRMask(32, 32),
			}, nil
		}
	}

	return net.IPNet{}, domain.ErrNoFreePeerIP
}

func countFreeAddrs(device *wgtypes.Device) (int, error) {
	info, err := getSubnetInfo(device)
	if err != nil {
		return 0, err
	}

	count := 0
	for addr := info.network + 1; addr < info.broadcast; addr++ {
		if !info.used[addr] {
			count++
		}
	}

	return count, nil
}

func getWgAddr(deviceName string) (net.IPNet, error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return net.IPNet{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return net.IPNet{}, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.IsLoopback() {
				continue
			}
			if ipnet.IP.To4() == nil {
				continue
			}
			return net.IPNet{
				IP:   ipnet.IP.To4(),
				Mask: ipnet.Mask,
			}, nil
		}
	}
	return net.IPNet{}, fmt.Errorf("could not find IP of %v", deviceName)
}
