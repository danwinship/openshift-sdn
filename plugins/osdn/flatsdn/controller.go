package flatsdn

import (
	"encoding/hex"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"os/exec"
	"syscall"

	"github.com/openshift/openshift-sdn/pkg/netutils"
	"github.com/openshift/openshift-sdn/plugins/osdn/api"
)

type FlowController struct {
	nodeIP     string
	nodeMAC    string
	nodeSubnet *net.IPNet
}

func NewFlowController() *FlowController {
	return &FlowController{}
}

func (c *FlowController) Setup(nodeIP, localSubnetCIDR, clusterNetworkCIDR, servicesNetworkCIDR string, mtu uint) error {
	var err error
	c.nodeIP = nodeIP
	c.nodeSubnet, err = netutils.GetNodeSubnet(nodeIP)
	if err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(localSubnetCIDR)
	localSubnetMaskLength, _ := ipnet.Mask.Size()
	localSubnetGateway := netutils.GenerateDefaultGateway(ipnet).String()
	out, err := exec.Command("openshift-sdn-kube-subnet-setup.sh", localSubnetGateway, localSubnetCIDR, fmt.Sprint(localSubnetMaskLength), clusterNetworkCIDR, servicesNetworkCIDR, fmt.Sprint(mtu)).CombinedOutput()
	log.Infof("Output of setup script:\n%s", out)
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok {
			status := exitErr.ProcessState.Sys().(syscall.WaitStatus)
			if status.Exited() && status.ExitStatus() == 140 {
				// valid, do nothing, its just a benevolent restart
				return nil
			}
		}
		log.Errorf("Error executing setup script. \n\tOutput: %s\n\tError: %v\n", out, err)
		return err
	}

	c.nodeMAC, err = netutils.GetInterfaceMAC("tun0")
	if err != nil {
		return err
	}

	_, err = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "del-flows", "br0").CombinedOutput()
	if err != nil {
		return err
	}
	_, err = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", "cookie=0x0,table=0,priority=50,actions=output:2").CombinedOutput()
	arprule := fmt.Sprintf("cookie=0x0,table=0,priority=100,arp,nw_dst=%s,actions=output:2", localSubnetGateway)
	iprule := fmt.Sprintf("cookie=0x0,table=0,priority=100,ip,nw_dst=%s,actions=output:2", localSubnetGateway)
	_, err = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", arprule).CombinedOutput()
	_, err = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", iprule).CombinedOutput()
	return err
}

func (c *FlowController) AddOFRules(nodeIP, nodeSubnetCIDR string) error {
	cookie := generateCookie(nodeIP)
	if nodeIP == c.nodeIP {
		// self, so add the input rules for containers that are not processed through kube-hooks
		// for the input rules to pods, see the kube-hook
		iprule := fmt.Sprintf("table=0,cookie=0x%s,priority=75,ip,nw_dst=%s,actions=output:9", cookie, nodeSubnetCIDR)
		arprule := fmt.Sprintf("table=0,cookie=0x%s,priority=75,arp,nw_dst=%s,actions=output:9", cookie, nodeSubnetCIDR)
		o, e := exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", iprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", iprule, o, e)
		o, e = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", arprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", arprule, o, e)
		return e
	} else if c.nodeMAC != "" && c.nodeSubnet.Contains(net.ParseIP(nodeIP)) {
		o, e := exec.Command("ip", "route", "add", nodeSubnetCIDR, "via", nodeIP).CombinedOutput()
		log.Infof("Output of adding ip route: %s (%v)", o, e)
		iprule := fmt.Sprintf("table=0,cookie=0x%s,priority=100,ip,nw_dst=%s,actions=set_field:%s->eth_dst,output:2", cookie, nodeSubnetCIDR, c.nodeMAC)
		arprule := fmt.Sprintf("table=0,cookie=0x%s,priority=100,arp,nw_dst=%s,actions=set_field:%s->tun_dst,output:1", cookie, nodeSubnetCIDR, nodeIP)
		o, e = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", iprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", iprule, o, e)
		o, e = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", arprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", arprule, o, e)
		return e
	} else {
		iprule := fmt.Sprintf("table=0,cookie=0x%s,priority=100,ip,nw_dst=%s,actions=set_field:%s->tun_dst,output:1", cookie, nodeSubnetCIDR, nodeIP)
		arprule := fmt.Sprintf("table=0,cookie=0x%s,priority=100,arp,nw_dst=%s,actions=set_field:%s->tun_dst,output:1", cookie, nodeSubnetCIDR, nodeIP)
		o, e := exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", iprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", iprule, o, e)
		o, e = exec.Command("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "br0", arprule).CombinedOutput()
		log.Infof("Output of adding %s: %s (%v)", arprule, o, e)
		return e
	}
	return nil
}

func (c *FlowController) DelOFRules(nodeIP, nodeSubnetCIDR string) error {
	log.Infof("Calling del rules for %s", nodeIP)
	cookie := generateCookie(nodeIP)
	if c.nodeSubnet.Contains(net.ParseIP(nodeIP)) {
		o, e := exec.Command("ip", "route", "delete", nodeSubnetCIDR, "via", nodeIP).CombinedOutput()
		if e != nil {
			log.Infof("Output of deleting ip route (ignored): %s (%v)", o, e)
		}
	}

	rule := fmt.Sprintf("table=0,cookie=0x%s/0xffffffff", cookie)
	o, e := exec.Command("ovs-ofctl", "-O", "OpenFlow13", "del-flows", "br0", rule).CombinedOutput()
	log.Infof("Output of deleting flows: %s (%v)", o, e)
	return e
}

func generateCookie(ip string) string {
	return hex.EncodeToString(net.ParseIP(ip).To4())
}

func (c *FlowController) AddServiceOFRules(netID uint, IP string, protocol api.ServiceProtocol, port uint) error {
	return nil
}

func (c *FlowController) DelServiceOFRules(netID uint, IP string, protocol api.ServiceProtocol, port uint) error {
	return nil
}

func (c *FlowController) UpdatePod(namespace, podName, containerID string, netID uint) error {
	return nil
}
