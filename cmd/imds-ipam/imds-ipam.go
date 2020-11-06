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
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/awsutils"
)

var version string

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.SetPrefix("CNI imds-ipam: ")
	log.SetOutput(os.Stderr) // NB: ends up in kubelet syslog

	rand.Seed(time.Now().UnixNano())

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniversion.All, fmt.Sprintf("imds-ipam CNI plugin %s", version))
}

type NetConfIgnoreInterfaceTerm struct {
	// Ignore DeviceIndex in range [Start,End)
	DeviceIndexStart int `json:"deviceIndexStart"`
	DeviceIndexEnd   int `json:"deviceIndexEnd"`
}

// IPAMConf is our CNI (IPAM) config structure
type IPAMConf struct {
	types.IPAM

	Routes  []*types.Route `json:"routes"`
	DataDir string         `json:"dataDir"`

	// Interfaces to ignore (ignores interfaces matching any term)
	IgnoreInterfaces []NetConfIgnoreInterfaceTerm `json:"ignoreInterfaces"`
}

// NetConf is our CNI config structure
type NetConf struct {
	CNIVersion string `json:"cniVersion,omitempty"`

	Name string    `json:"name,omitempty"`
	IPAM *IPAMConf `json:"ipam,omitempty"`
}

func loadConf(bytes []byte) (*NetConf, *IPAMConf, error) {
	n := &NetConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, nil, err
	}

	if n.IPAM == nil {
		return nil, nil, fmt.Errorf("IPAM config missing 'ipam' key")
	}

	return n, n.IPAM, nil
}

func cmdCheck(args *skel.CmdArgs) error {
	//log.Printf("CHECK: %v", args)

	netConf, ipamConf, err := loadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	store := NewStore(filepath.Join(ipamConf.DataDir, netConf.Name))
	if err := store.Open(); err != nil {
		return err
	}
	defer store.Close()

	ip := store.FindByID(args.ContainerID, args.IfName)
	if ip == nil {
		return fmt.Errorf("imds-ipam: Failed to find address added by container %s", args.ContainerID)
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	ctx := context.TODO()

	//log.Printf("ADD: %v", args)

	netConf, ipamConf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	session, err := session.NewSession()
	if err != nil {
		return err
	}
	awsConfig := aws.NewConfig()
	imds := awsutils.TypedIMDS{awsutils.NewCachedIMDS(ec2metadata.New(session, awsConfig))}

	result := &current.Result{}

	store := NewStore(filepath.Join(ipamConf.DataDir, netConf.Name))
	if err := store.Open(); err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			panic(err)
		}
	}()

	allocator := NewIMDSAllocator(imds, store)

	ipConf, err := allocator.Get(ctx, args.ContainerID, args.IfName, "4")
	if err != nil {
		return err
	}
	result.IPs = append(result.IPs, &ipConf)

	result.Routes = ipamConf.Routes

	//log.Printf("ADD returning %v", result)

	return types.PrintResult(result, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ctx := context.TODO()

	//log.Printf("DEL: %v", args)

	netConf, ipamConf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	session, err := session.NewSession()
	if err != nil {
		return err
	}
	awsConfig := aws.NewConfig()
	imds := awsutils.TypedIMDS{awsutils.NewCachedIMDS(ec2metadata.New(session, awsConfig))}

	store := NewStore(filepath.Join(ipamConf.DataDir, netConf.Name))
	if err := store.Open(); err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			panic(err)
		}
	}()

	allocator := NewIMDSAllocator(imds, store)

	if err := allocator.Put(ctx, args.ContainerID, args.IfName, "4"); err != nil {
		return err
	}

	return nil
}
