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
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/vishvananda/netlink"
)

var version string

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// NetConf is our CNI config structure
type NetConf struct {
	types.NetConf

	// IP to use as SNAT target.
	SnatIP net.IP `json:"snatIP"`
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, err
	}

	if n.RawPrevResult != nil {
		if err := cniversion.ParsePrevResult(&n.NetConf); err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
	}
	return n, nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniversion.All, fmt.Sprintf("egress-v4 CNI plugin %s", version))
}

func cmdCheck(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	prevResult, err := current.GetResult(netConf.PrevResult)
	if err != nil {
		return err
	}

	chain := utils.MustFormatChainNameWithPrefix(netConf.Name, args.ContainerID, "E4-")
	comment := utils.FormatComment(netConf.Name, args.ContainerID)

	if netConf.SnatIP != nil {
		for _, ipc := range prevResult.IPs {
			if ipc.Version == "4" {
				if err := snat4Check(netConf.SnatIP, ipc.Address.IP, chain, comment); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	prevResult, err := current.GetResult(netConf.PrevResult)
	if err != nil {
		return err
	}

	for _, ipc := range prevResult.IPs {
		if ipc.Version == "4" {
			// Already has an IPv4 address somehow, just
			// do nothing and exit.
			return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
		}
	}

	chain := utils.FormatChainName(netConf.Name, args.ContainerID)
	comment := utils.FormatComment(netConf.Name, args.ContainerID)

	ipamResultI, err := ipam.ExecAdd(netConf.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(netConf.IPAM.Type, args.StdinData)
		}
	}()

	ipamResult, err := current.NewResultFromResult(ipamResultI)
	if err != nil {
		return err
	}

	if len(ipamResult.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned zero IPs")
	}

	contIfIdx := -1
	hostIfIdx := -1
	for i, iface := range prevResult.Interfaces {
		if iface.Sandbox != "" && iface.Name == args.IfName {
			contIfIdx = i
		}
		if iface.Sandbox == "" {
			hostIfIdx = i
		}
	}
	if contIfIdx == -1 {
		return fmt.Errorf("failed to find %s in chained result", args.IfName)
	}

	if err := ip.EnableForward(ipamResult.IPs); err != nil {
		return fmt.Errorf("could not enable IP forwarding: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Use existing container interface from previous plugin
	ipamResult.Interfaces = prevResult.Interfaces
	for _, ipc := range ipamResult.IPs {
		ipc.Interface = &contIfIdx
	}

	err = netns.Do(func(hostNS ns.NetNS) error {
		return ipam.ConfigureIface(args.IfName, ipamResult)
	})
	if err != nil {
		return err
	}

	if hostIfIdx != -1 {
		hostIfName := ipamResult.Interfaces[hostIfIdx].Name
		link, err := netlink.LinkByName(hostIfName)
		if err != nil {
			return fmt.Errorf("failed to find host interface %q: %v", hostIfName, err)
		}
		for _, ipc := range ipamResult.IPs {
			addrBits := 32
			if ipc.Version == "6" {
				addrBits = 128
			}
			err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   ipc.Gateway,
					Mask: net.CIDRMask(addrBits, addrBits),
				},
				Label: "",
			})
			if err != nil {
				return fmt.Errorf("failed to add gateway address %s to host interface %q: %v", ipc.Gateway, hostIfName, err)
			}

			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP,
					Mask: net.CIDRMask(addrBits, addrBits),
				},
				Scope: netlink.SCOPE_LINK,
			})
			if err != nil {
				return fmt.Errorf("failed to add host route to %s through interface %q: %v", ipc.Address.IP, hostIfName, err)
			}
		}
	}

	if netConf.SnatIP != nil {
		for _, ipc := range ipamResult.IPs {
			if ipc.Version == "4" {
				if err := snat4(netConf.SnatIP, ipc.Address.IP, chain, comment); err != nil {
					return err
				}
			}
		}
	}

	// Pass through the previous result
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	var addrs []netlink.Addr
	if args.Netns != "" {
		err := ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
			iface, err := netlink.LinkByName(args.IfName)
			if err != nil {
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					return nil
				}
				return err
			}
			addrs, err = netlink.AddrList(iface, netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	chain := utils.FormatChainName(netConf.Name, args.ContainerID)
	comment := utils.FormatComment(netConf.Name, args.ContainerID)

	if netConf.SnatIP != nil {
		for _, addr := range addrs {
			if err := snat4Del(addr.IPNet.IP, chain, comment); err != nil {
				return err
			}
		}
	}

	if err := ipam.ExecDel(netConf.IPAM.Type, args.StdinData); err != nil {
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	return nil
}
