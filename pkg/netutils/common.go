package netutils

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"

	kerrors "k8s.io/kubernetes/pkg/util/errors"
)

func IPToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func Uint32ToIP(u uint32) net.IP {
	ip := make([]byte, 4)
	binary.BigEndian.PutUint32(ip, u)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3])
}

// Generate the default gateway IP Address for a subnet
func GenerateDefaultGateway(sna *net.IPNet) net.IP {
	ip := sna.IP.To4()
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]|0x1)
}

func GetHostIPNetworks(skipInterfaces []string) ([]*net.IPNet, error) {
	hostInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	errList := []error{}
	var hostIPNets []*net.IPNet

CheckValidInterfaces:
	for _, iface := range hostInterfaces {
		for _, skipIface := range skipInterfaces {
			if skipIface == iface.Name {
				continue CheckValidInterfaces
			}
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			errList = append(errList, err)
			continue
		}
		for _, addr := range ifAddrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				errList = append(errList, err)
				continue
			}
			// Skip IP addrs that doesn't belong to IPv4
			if ip.To4() != nil {
				hostIPNets = append(hostIPNets, ipNet)
			}
		}
	}
	return hostIPNets, kerrors.NewAggregate(errList)
}

func GetNodeIP(nodeName string) (string, error) {
	ip := net.ParseIP(nodeName)
	if ip == nil {
		addrs, err := net.LookupIP(nodeName)
		if err != nil {
			return "", fmt.Errorf("Failed to lookup IP address for node %s: %v", nodeName, err)
		}
		for _, addr := range addrs {
			if addr.String() != "127.0.0.1" {
				ip = addr
				break
			}
		}
	}
	if ip == nil || len(ip.String()) == 0 {
		return "", fmt.Errorf("Failed to obtain IP address from node name: %s", nodeName)
	}
	return ip.String(), nil
}

func GetNodeSubnet(nodeIP string) (*net.IPNet, error) {
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		return nil, fmt.Errorf("Invalid nodeIP: %s", nodeIP)
	}

	routes, err := exec.Command("ip", "route").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Could not execute 'ip route': %s", err)
	}
	for _, route := range strings.Split(string(routes), "\n") {
		words := strings.Split(route, " ")
		if len(words) == 0 || words[0] == "default" {
			continue
		}
		_, network, err := net.ParseCIDR(words[0])
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return network, nil
		}
	}
	return nil, fmt.Errorf("Could not find subnet for node %s", nodeIP)
}

func GetInterfaceMAC(ifname string) (string, error) {
	output, err := exec.Command("ip", "link", "show", ifname).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Could not execute 'ip link show %s': %s", ifname, err)
	}

	outstring := string(output)
	i := strings.Index(outstring, "link/ether ")
	if i != -1 {
		// "link/ether " is 11 bytes, MAC addr is 17 beyond that
		return outstring[i+11:i+28], nil
	}

	return "", nil
}
