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
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// test-plugin is in this directory
const testPluginDir = "../../testdata"

var defaultRoute4 = net.IPNet{
	IP:   net.IPv4zero,
	Mask: net.IPv4Mask(0, 0, 0, 0),
}

var _ = Describe("egress-v4 Operations", func() {
	var originalNs, targetNs ns.NetNS
	const IFNAME = "myeth0"
	var origPath string

	BeforeEach(func() {
		extraPath, err := filepath.Abs(testPluginDir)
		Expect(err).NotTo(HaveOccurred())
		origPath = os.Getenv("PATH")
		os.Setenv("PATH", fmt.Sprintf("%s%c%s", extraPath, os.PathListSeparator, origPath))
	})
	AfterEach(func() {
		os.Setenv("PATH", origPath)
	})

	BeforeEach(func() {
		// Run test in a temp NetNS
		var err error
		originalNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})
	AfterEach(func() {
		Expect(originalNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(originalNs)).To(Succeed())
	})

	BeforeEach(func() {
		var err error
		targetNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})
	AfterEach(func() {
		Expect(targetNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(targetNs)).To(Succeed())
	})

	It("aborts cleanly if not run as a chained plugin", func() {

		conf := `{
  "cniVersion": "0.3.0",
  "name": "mynet",
  "type": "egress-v4"
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      IFNAME,
			StdinData:   []byte(conf),
		}

		err := originalNs.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			return err
		})
		Expect(err).To(MatchError(ContainSubstring("must be called as a chained plugin")))

	})

	It("does nothing if IPv4 already configured", func() {

		conf := `{
  "cniVersion": "0.3.1",
  "name": "mynet",
  "type": "egress-v4",
  "prevResult": {
    "cniVersion": "0.3.1",
    "ips": [{
      "version": "4",
      "address": "192.0.2.27/24"
    }]
  },
  "ipam": {
    "type": "test-plugin"
  }
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      IFNAME,
			StdinData:   []byte(conf),
		}

		err := originalNs.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			return err
		})
		Expect(err).NotTo(HaveOccurred())
	})

	When("chained after IPv6 ptp-ish plugin", func() {
		// The following fake ptp-like code configures veth pair with:
		//
		// Container:
		//   myeth0 with 2001:db8:1::100/64
		//   default via 2001:db8:1::1 dev myeth0
		// Host:
		//   vethX with 2001:db8:1::1/128
		//   2001:db8:1::1/128 dev vethX
		//
		var prevResult current.Result
		contIP := net.ParseIP("2001:db8:1::100")
		hostIP := net.ParseIP("2001:db8:1::1")

		JustBeforeEach(func() {
			contIfIdx := 1 // contVeth
			result := current.Result{
				CNIVersion: "0.3.1",
				IPs: []*current.IPConfig{{
					Version:   "6",
					Interface: &contIfIdx,
					Address: net.IPNet{
						IP:   contIP,
						Mask: net.CIDRMask(64, 128),
					},
					Gateway: hostIP,
				}},
				Routes: []*types.Route{{
					Dst: net.IPNet{
						IP:   net.IPv6zero,
						Mask: net.CIDRMask(0, 128),
					},
				}},
			}

			err := targetNs.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				hostVeth, contVeth, err := ip.SetupVeth(IFNAME, 1500, originalNs)
				Expect(err).NotTo(HaveOccurred())

				result.Interfaces = []*current.Interface{
					{
						Name: hostVeth.Name,
						Mac:  hostVeth.HardwareAddr.String(),
					},
					{
						Name:    contVeth.Name,
						Mac:     contVeth.HardwareAddr.String(),
						Sandbox: targetNs.Path(),
					},
				}

				Expect(ipam.ConfigureIface(IFNAME, &result)).
					To(Succeed())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			err = originalNs.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				veth, err := netlink.LinkByName(result.Interfaces[0].Name)
				Expect(err).NotTo(HaveOccurred())

				addr := &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   hostIP,
						Mask: net.CIDRMask(128, 128),
					},
					Label: "",
				}
				Expect(netlink.AddrAdd(veth, addr)).To(Succeed())

				Expect(netlink.RouteAdd(&netlink.Route{
					LinkIndex: veth.Attrs().Index,
					Dst: &net.IPNet{
						IP:   contIP,
						Mask: net.CIDRMask(128, 128),
					},
					Scope: netlink.SCOPE_HOST,
				})).
					To(Succeed())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			prevResult = result
		})

		When("on a fake network", func() {
			var internetNs ns.NetNS
			primaryIP := net.IPNet{
				IP:   net.IPv4(198, 51, 100, 10),
				Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0),
			}
			gatewayIP := net.IPv4(198, 51, 100, 1)

			BeforeEach(func() {
				var err error
				internetNs, err = testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
			})
			AfterEach(func() {
				Expect(internetNs.Close()).To(Succeed())
				Expect(testutils.UnmountNS(internetNs)).To(Succeed())
			})

			JustBeforeEach(func() {
				var internetVeth, hostVeth net.Interface

				err := originalNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					var err error
					internetVeth, hostVeth, err = ip.SetupVeth("eth0", 1500, internetNs)
					Expect(err).NotTo(HaveOccurred())

					veth, err := netlink.LinkByName(hostVeth.Name)
					Expect(err).NotTo(HaveOccurred())

					Expect(netlink.AddrAdd(veth, &netlink.Addr{
						IPNet: &primaryIP,
						Label: "",
					})).
						To(Succeed())

					Expect(netlink.RouteAdd(&netlink.Route{
						LinkIndex: veth.Attrs().Index,
						Dst:       &defaultRoute4,
						Scope:     netlink.SCOPE_UNIVERSE,
					})).
						To(Succeed())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				err = internetNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					veth, err := netlink.LinkByName(internetVeth.Name)
					Expect(err).NotTo(HaveOccurred())

					Expect(netlink.AddrAdd(veth, &netlink.Addr{
						IPNet: &net.IPNet{
							IP:   gatewayIP,
							Mask: primaryIP.Mask,
						},
						Label: "",
					})).To(Succeed())

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("configures and deconfigures SNAT IP with ADD/DEL", func() {
				By("running ADD")

				contIP4 := net.ParseIP("192.0.2.10")
				hostIP4 := net.ParseIP("192.0.2.1")

				os.Setenv("TEST_PLUGIN_RESULT", `{
  "cniVersion": "0.3.0",
  "ips": [{
      "version": "4",
      "address": "192.0.2.10/24",
      "gateway": "192.0.2.1"
  }],
  "routes": [{"dst": "0.0.0.0/0"}]
}
`)

				prevResultRaw, err := json.Marshal(prevResult)
				Expect(err).NotTo(HaveOccurred())

				conf := fmt.Sprintf(`{
  "cniVersion": "0.3.1",
  "name": "mynet",
  "type": "egress-v4",
  "prevResult": %s,
  "snatIP": "198.51.100.10",
  "ipam": {
    "type": "test-plugin"
  }
}`,
					string(prevResultRaw))

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       targetNs.Path(),
					IfName:      IFNAME,
					StdinData:   []byte(conf),
				}

				var resI types.Result
				var res *current.Result

				err = originalNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					var err error
					resI, _, err = testutils.CmdAddWithArgs(args, func() error {
						return cmdAdd(args)
					})
					return err
				})
				Expect(err).NotTo(HaveOccurred())

				res, err = current.NewResultFromResult(resI)
				Expect(err).NotTo(HaveOccurred())

				// Plugin output should _not_ include egress v4 address
				Expect(res.IPs).To(HaveLen(1))
				Expect(res.IPs[0].Version).To(Equal("6"))
				Expect(res.IPs[0].Address.IP).To(Equal(contIP))

				err = targetNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					link, err := netlink.LinkByName(IFNAME)
					Expect(err).NotTo(HaveOccurred())

					addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
					Expect(err).NotTo(HaveOccurred())
					Expect(addrs).To(HaveLen(1))
					Expect(addrs[0].IPNet).To(Equal(&net.IPNet{
						IP:   contIP4.To4(),
						Mask: net.CIDRMask(24, 32),
					}))

					// v6 should continue to work
					if err := testutils.Ping(contIP.String(), hostIP.String(), true, 30); err != nil {
						return fmt.Errorf("ping %s -> %s failed: %s", contIP, hostIP, err)
					}

					// v4 to host should work
					if err := testutils.Ping(contIP4.String(), hostIP4.String(), false, 30); err != nil {
						return fmt.Errorf("ping %s -> %s failed: %s", contIP4, hostIP4, err)
					}

					// v4 to "Internet" should work
					// TODO: verify SNAT IP (via echo server)
					if err := testutils.Ping(contIP4.String(), gatewayIP.String(), false, 30); err != nil {
						return fmt.Errorf("ping %s -> %s failed: %s", contIP4, gatewayIP, err)
					}

					return nil
				})
				Expect(err).NotTo(HaveOccurred())

				By("running CHECK")

				// NB: CHECK is only defined for cniVersion 0.4.0+
				checkConf := fmt.Sprintf(`{
  "cniVersion": "0.4.0",
  "name": "mynet",
  "type": "egress-v4",
  "prevResult": %s,
  "snatIP": "198.51.100.10",
  "ipam": {
    "type": "test-plugin"
  }
}`,
					string(prevResultRaw))

				args.StdinData = []byte(checkConf)

				err = originalNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()
					return testutils.CmdCheckWithArgs(args, func() error { return cmdCheck(args) })
				})
				Expect(err).NotTo(HaveOccurred())

				By("running DEL")

				args.StdinData = []byte(conf)

				err = originalNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					return testutils.CmdDelWithArgs(args, func() error {
						return cmdDel(args)
					})
				})
				Expect(err).NotTo(HaveOccurred())

				err = originalNs.Do(func(ns.NetNS) error {
					defer GinkgoRecover()

					ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
					Expect(err).NotTo(HaveOccurred())

					rules, err := ipt.List("nat", "POSTROUTING")
					Expect(err).NotTo(HaveOccurred())

					// Verify SNAT rule has gone
					Expect(rules).To(ConsistOf([]string{"-P POSTROUTING ACCEPT"}))

					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
