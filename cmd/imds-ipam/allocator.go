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
	"fmt"
	"math/rand"
	"net"

	"github.com/containernetworking/cni/pkg/types/current"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/awsutils"
)

type IMDSAllocator struct {
	store  Store
	client awsutils.TypedIMDS
}

func NewIMDSAllocator(imds awsutils.EC2MetadataIface, store Store) *IMDSAllocator {
	return &IMDSAllocator{
		store:  store,
		client: awsutils.TypedIMDS{imds},
	}
}

func (a *IMDSAllocator) Get(ctx context.Context, id, ifname, version string) (current.IPConfig, error) {
	macs, err := a.client.GetMACs(ctx)
	if err != nil {
		return current.IPConfig{}, err
	}

	primaryIP, err := a.client.GetLocalIPv4(ctx)
	if err != nil {
		return current.IPConfig{}, err
	}

	// Shuffle so crash-looping containers at least try with
	// different IPs.
	// TODO: Better: store the mac/ip cursor and round-robin like
	// host-local does.
	rand.Shuffle(len(macs), func(i, j int) {
		macs[i], macs[j] = macs[j], macs[i]
	})

	for _, mac := range macs {
		// TODO: skip interface if ignored

		var ips []net.IP
		var subnet net.IPNet
		if version == "4" {
			ips, err = a.client.GetLocalIPv4s(ctx, mac)
			if err != nil {
				return current.IPConfig{}, err
			}

			subnet, err = a.client.GetSubnetIPv4CIDRBlock(ctx, mac)
			if err != nil {
				return current.IPConfig{}, err
			}
		} else {
			ips, err = a.client.GetIPv6s(ctx, mac)
			if err != nil {
				return current.IPConfig{}, err
			}
			subnet, err = a.client.GetSubnetIPv6CIDRBlock(ctx, mac)
			if err != nil {
				return current.IPConfig{}, err
			}
		}

		// Skip primary IP
		ips = ips[1:]

		rand.Shuffle(len(ips), func(i, j int) {
			ips[i], ips[j] = ips[j], ips[i]
		})

		for _, ip := range ips {
			switch err := a.store.ReserveIP(id, ifname, ip); err {
			case nil:
				result := current.IPConfig{
					Version: version,
					Address: net.IPNet{IP: ip, Mask: subnet.Mask},
					Gateway: primaryIP,
				}
				return result, nil
			case ErrAlreadyReserved:
				continue
			default:
				return current.IPConfig{}, err
			}
		}
	}

	return current.IPConfig{}, fmt.Errorf("no IP addresses available")
}

func (a *IMDSAllocator) Put(ctx context.Context, id, ifname, version string) error {
	a.store.ReleaseID(id, ifname)
	return nil
}
