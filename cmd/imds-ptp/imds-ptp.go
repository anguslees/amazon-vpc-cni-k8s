// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-iptables/iptables"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/awsutils"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"
)

var version string

const (
	// Order matters
	rulePriorityLocalPods   = 30000
	rulePriorityMasq        = 30010
	rulePriorityOutgoingENI = 30020

	masqMark = 0x80
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// NetConf is our CNI config structure
type NetConf struct {
	types.NetConf

	MTU int `json:"mtu"`
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, err
	}

	return n, nil
}

// Mostly based on standard ptp CNI plugin
func setupContainerVeth(netns ns.NetNS, ifName string, mtu int, pr *current.Result) (*current.Interface, *current.Interface, error) {
	// The IPAM result will be something like IP=192.168.3.5/24, GW=192.168.3.1.
	// What we want is really a point-to-point link but veth does not support IFF_POINTTOPOINT.
	// Next best thing would be to let it ARP but set interface to 192.168.3.5/32 and
	// add a route like "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// Unfortunately that won't work as the GW will be outside the interface's subnet.

	// Our solution is to configure the interface with 192.168.3.5/24, then delete the
	// "192.168.3.0/24 dev $ifName" route that was automatically added. Then we add
	// "192.168.3.1/32 dev $ifName" and "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// In other words we force all traffic to ARP via the gateway except for GW itself.

	hostInterface := &current.Interface{}
	containerInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		containerInterface.Name = contVeth0.Name
		containerInterface.Mac = contVeth0.HardwareAddr.String()
		containerInterface.Sandbox = netns.Path()

		for _, ipc := range pr.IPs {
			// All addresses apply to the container veth interface
			ipc.Interface = current.Int(1)
		}

		pr.Interfaces = []*current.Interface{hostInterface, containerInterface}

		if err = ipam.ConfigureIface(ifName, pr); err != nil {
			return err
		}

		contVeth, err := net.InterfaceByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", ifName, err)
		}

		for _, ipc := range pr.IPs {
			// Delete the route that was automatically added
			route := netlink.Route{
				LinkIndex: contVeth.Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
					Mask: ipc.Address.Mask,
				},
				Scope: netlink.SCOPE_NOWHERE,
			}

			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %v: %v", route, err)
			}

			addrBits := 32
			if ipc.Version == "6" {
				addrBits = 128
			}

			for _, r := range []netlink.Route{
				{
					LinkIndex: contVeth.Index,
					Dst: &net.IPNet{
						IP:   ipc.Gateway,
						Mask: net.CIDRMask(addrBits, addrBits),
					},
					Scope: netlink.SCOPE_LINK,
					Src:   ipc.Address.IP,
				},
				{
					LinkIndex: contVeth.Index,
					Dst: &net.IPNet{
						IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
						Mask: ipc.Address.Mask,
					},
					Scope: netlink.SCOPE_UNIVERSE,
					Gw:    ipc.Gateway,
					Src:   ipc.Address.IP,
				},
			} {
				if err := netlink.RouteAdd(&r); err != nil {
					return fmt.Errorf("failed to add route %v: %v", r, err)
				}
			}
		}

		// Send a gratuitous arp for all v4 addresses
		for _, ipc := range pr.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, containerInterface, nil
}

func setupHostVeth(vethName string, result *current.Result) error {
	// hostVeth moved namespaces and may have a new ifindex
	veth, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	for _, ipc := range result.IPs {
		maskLen := 128
		if ipc.Address.IP.To4() != nil {
			maskLen = 32
		}

		// NB: this is modified from standard ptp plugin.

		ipn := &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: veth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       ipn,
		})
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to add route on host: %v", err)
		}
	}

	return nil
}

func setupHostEni(ec2Metadata awsutils.EC2MetadataIface, procSys procsyswrapper.ProcSys, mtu int, vethName string, result *current.Result) error {
	ctx := context.TODO()

	imds := awsutils.TypedIMDS{ec2Metadata}

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	interfaceByMAC := make(map[string]*net.Interface, len(ifaces))
	for i := range ifaces {
		iface := ifaces[i]
		interfaceByMAC[iface.HardwareAddr.String()] = &iface
	}

	primaryMAC, err := imds.GetMAC(ctx)
	if err != nil {
		return err
	}
	primaryIface := interfaceByMAC[primaryMAC]
	if primaryIface == nil {
		return fmt.Errorf("failed to find interface for MAC %s", primaryMAC)
	}

	for _, ipc := range result.IPs {
		// Setup ENI interface and policy route.  This IP has
		// to go out the right ENI (to satisfy the AWS src/dst
		// check).

		getIPs := imds.GetLocalIPv4s
		getSubnet := imds.GetSubnetIPv4CIDRBlock
		defaultRoute := net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}
		family := unix.AF_INET
		maskLen := 32
		iptProto := iptables.ProtocolIPv4
		if ipc.Version == "6" {
			getIPs = imds.GetIPv6s
			getSubnet = imds.GetSubnetIPv6CIDRBlock
			defaultRoute = net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			}
			family = unix.AF_INET6
			maskLen = 128
			iptProto = iptables.ProtocolIPv6
		}

		ipt, err := iptables.NewWithProtocol(iptProto)
		if err != nil {
			return err
		}

		// Hack? Lookup specific routes (to other containers)
		// in main table first.  Ideally we would split all
		// the specific and fallback routes out of main, and
		// put them in properly ordered rules - but that
		// requires *all* other network config to Do The Right
		// Thing too.  FIXME: just replace with with a
		// more normal to-each-container route table.
		rule := netlink.NewRule()
		rule.Priority = rulePriorityLocalPods
		rule.Family = family
		rule.SuppressPrefixlen = 8*maskLen - 1
		rule.Table = unix.RT_TABLE_MAIN
		if err := netlink.RuleAdd(rule); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add rule: %v", err)
			}
		}

		// kube-proxy DNATs+MASQUERADEs traffic to
		// nodeports. The problem is that this rewrites
		// everything to be to/from primaryIP (eth0) *after*
		// policy routing has already chosen some other
		// interface - rp_filter freaks out, packet goes out
		// wrong interface, etc, etc.
		// Solution: mark packets that look like nodeports in
		// iptables (before routing), and ensure the routing
		// chooses eth0.  Sigh. :(
		iptRules := [][]string{
			{
				"-m", "comment", "--comment", "AWS, primary ENI",
				"-i", primaryIface.Name,
				"-m", "addrtype", "--dst-type", "LOCAL", "--limit-iface-in",
				"-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#x/%#x", masqMark, masqMark),
			},
			{
				"-m", "comment", "--comment", "AWS, container return",
				"-i", vethName, "-j", "CONNMARK", "--restore-mark", "--mask", fmt.Sprintf("%#x", masqMark),
			},
		}
		for _, iptRule := range iptRules {
			if err := ipt.AppendUnique("mangle", "PREROUTING", iptRule...); err != nil {
				return err
			}
		}
		rule = netlink.NewRule()
		rule.Priority = rulePriorityMasq
		rule.Mark = masqMark
		rule.Mask = masqMark
		rule.Family = family
		rule.Table = unix.RT_TABLE_MAIN
		if err := netlink.RuleAdd(rule); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add rule: %v", err)
			}
		}

		// Find related ENI
		macs, err := imds.GetMACs(ctx)
		if err != nil {
			return err
		}

		var eniMAC string
	macloop:
		for _, mac := range macs {
			ips, err := getIPs(ctx, mac)
			if err != nil {
				return err
			}

			for _, ip := range ips {
				if ip.Equal(ipc.Address.IP) {
					eniMAC = mac
					break macloop
				}
			}
		}
		if eniMAC == "" {
			return fmt.Errorf("failed to find ENI for %s", ipc.Address)
		}

		eniIface, ok := interfaceByMAC[eniMAC]
		if !ok {
			return fmt.Errorf("failed to find existing interface with MAC %s", eniMAC)
		}

		subnet, err := getSubnet(ctx, eniMAC)
		if err != nil {
			return err
		}

		deviceNumber, err := imds.GetDeviceNumber(ctx, eniMAC)
		if err != nil {
			return err
		}

		tableIdx := 10 + deviceNumber

		eniLink, err := netlink.LinkByIndex(eniIface.Index)
		if err != nil {
			return err
		}

		if err := netlink.LinkSetMTU(eniLink, mtu); err != nil {
			return err
		}

		if err := netlink.LinkSetUp(eniLink); err != nil {
			return err
		}

		// Nodeport kube-proxy routing games requires "loose"
		// rp_filter.
		if ipc.Version == "4" {
			if err := procSys.Set(fmt.Sprintf("net/ipv4/conf/%s/rp_filter", primaryIface.Name), "2"); err != nil {
				return err
			}
		}

		routes := []netlink.Route{
			// subnet route
			{
				Table:     tableIdx,
				LinkIndex: eniIface.Index,
				Dst:       &subnet,
				Scope:     netlink.SCOPE_LINK,
			},
			// default route
			{
				Table:     tableIdx,
				LinkIndex: eniIface.Index,
				Dst:       &defaultRoute,
				Gw:        gatewayIP(subnet),
				Scope:     netlink.SCOPE_UNIVERSE,
			},
		}
		for _, r := range routes {
			if err := netlink.RouteAdd(&r); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("failed to add route (%s): %v", r, err)
				}
			}
		}

		rule = netlink.NewRule()
		rule.Priority = rulePriorityOutgoingENI
		rule.Table = tableIdx
		rule.Src = &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		if err := netlink.RuleAdd(rule); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add rule (%s): %v", rule, err)
			}
		}
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniversion.All, fmt.Sprintf("imds-ptp CNI plugin %s", version))
}

func cmdCheck(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// run the IPAM plugin and get back the config to apply
	err = ipam.ExecCheck(netConf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	if netConf.NetConf.RawPrevResult == nil {
		return fmt.Errorf("ptp: Required prevResult missing")
	}
	if err := cniversion.ParsePrevResult(&netConf.NetConf); err != nil {
		return err
	}
	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(netConf.PrevResult)
	if err != nil {
		return err
	}

	var contMap current.Interface
	// Find interfaces for name we know, that of host-device inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	//
	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container
		err := validateCniContainerInterface(contMap)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	session, err := session.NewSession()
	if err != nil {
		return err
	}
	awsConfig := aws.NewConfig().
		// Lots of retries: we have no better strategy available
		WithMaxRetries(20)

	ec2Metadata := awsutils.NewCachedIMDS(ec2metadata.New(session, awsConfig))

	procSys := procsyswrapper.NewProcSys()

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(netConf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(netConf.IPAM.Type, args.StdinData)
		}
	}()

	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned missing IP config")
	}

	if err := ip.EnableForward(result.IPs); err != nil {
		return fmt.Errorf("could not enable IP forwarding: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostInterface, _, err := setupContainerVeth(netns, args.IfName, netConf.MTU, result)
	if err != nil {
		return err
	}

	if err = setupHostVeth(hostInterface.Name, result); err != nil {
		return err
	}

	if err = setupHostEni(ec2Metadata, procSys, netConf.MTU, hostInterface.Name, result); err != nil {
		return err
	}

	if dnsConfSet(netConf.DNS) {
		result.DNS = netConf.DNS
	}

	return types.PrintResult(result, netConf.CNIVersion)
}

func dnsConfSet(dnsConf types.DNS) bool {
	return dnsConf.Nameservers != nil ||
		dnsConf.Search != nil ||
		dnsConf.Options != nil ||
		dnsConf.Domain != ""
}

func cmdDel(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if err := ipam.ExecDel(netConf.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		_, err = ip.DelLinkByNameAddr(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}
		return err
	})

	if err != nil {
		return err
	}

	return err
}

func validateCniContainerInterface(intf current.Interface) error {

	var link netlink.Link
	var err error

	if intf.Name == "" {
		return fmt.Errorf("container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("ptp: Container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return fmt.Errorf("ptp: Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return fmt.Errorf("container interface %s not of type veth/p2p", link.Attrs().Name)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return fmt.Errorf("ptp: Interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}

	return nil
}

// Router address isn't given in IMDS, so you just have to "know" that
// it is subnet .1 (or use DHCP) :(
func gatewayIP(subnet net.IPNet) net.IP {
	ip := subnet.IP.Mask(subnet.Mask)
	ip[len(ip)-1] |= 1
	return ip

}
