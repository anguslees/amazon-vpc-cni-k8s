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
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/awsutils"
)

var numENIs = flag.Int("enis", 0,
	"Number of ENIs to allocate, including primary ENI. 0 means maximum supported by instance type.")
var numIPs = flag.Int("ips", 0,
	"Number of IPs to allocate per ENI, including primary IP. 0 means maximum supported by instance type.")
var maxIPs = flag.Int("max-ips", 250,
	"Stop attaching ENIs after allocation at least this many IPs.")

func main() {
	flag.Parse()

	if err := doSetup(context.TODO()); err != nil {
		panic(err)
	}
}

func doSetup(ctx context.Context) error {
	session, err := session.NewSession()
	if err != nil {
		return err
	}
	awsConfig := aws.NewConfig().
		// Lots of retries: we have no better strategy available
		WithMaxRetries(20).
		WithLogLevel(aws.LogDebugWithRequestRetries)

	ec2Metadata := ec2metadata.New(session, awsConfig)
	region, err := ec2Metadata.Region()
	if err != nil {
		return err
	}

	ec2Svc := ec2.New(session, awsConfig.WithRegion(region))
	ec2Svc.Handlers.Send.PushBack(request.MakeAddToUserAgentHandler("attach-enis", "0"))

	if err := attachENIs(ctx, ec2Metadata, ec2Svc); err != nil {
		return err
	}

	return nil
}

// Create/attach all the desired ENIs.  In a ideal world, this would
// happen during boot in the launchtemplate, and we could remove this
// function.  Currently, ASG rejects launchtemplates that create more
// than one interface, however. :(
func attachENIs(ctx context.Context, ec2Metadata awsutils.EC2MetadataIface, ec2Svc ec2iface.EC2API) error {
	imds := awsutils.TypedIMDS{awsutils.NewCachedIMDS(ec2Metadata)}

	// NB: This is ~carefully written to make _no_ AWS API calls
	// unless necessary (excluding IMDS).

	instanceID, err := imds.GetInstanceID(ctx)
	if err != nil {
		return err
	}
	primaryMAC, err := imds.GetMAC(ctx)
	if err != nil {
		return err
	}
	sgIDs, err := imds.GetSecurityGroupIDs(ctx, primaryMAC)
	if err != nil {
		return err
	}
	subnetID, err := imds.GetSubnetID(ctx, primaryMAC)
	if err != nil {
		return err
	}

	availableIPs := 0
	devNums := make(map[int]string)

	macs, err := imds.GetMACs(ctx)
	if err != nil {
		return err
	}

	// Find existing ENI device numbers (read-only)
	for _, mac := range macs {
		num, err := imds.GetDeviceNumber(ctx, mac)
		if err != nil {
			return err
		}
		devNums[num] = mac

		ips, err := imds.GetLocalIPv4s(ctx, mac)
		if err != nil {
			return err
		}

		log.Printf("Found existing ENI (%s) with %d IPs", mac, len(ips))

		availableIPs += len(ips) - 1 // -1 for primary IP
		if availableIPs >= *maxIPs {
			// Found enough IPs, with nothing to do!
			log.Printf("Proceeding with at least %d available IPs across %d ENIs", availableIPs, len(devNums))
			return nil
		}
	}

	// Need to attach more ENIs/IPs

	if *numENIs == 0 || *numIPs == 0 {
		itype, err := imds.GetInstanceType(ctx)
		if err != nil {
			return err
		}

		ditOut, err := ec2Svc.DescribeInstanceTypesWithContext(ctx, &ec2.DescribeInstanceTypesInput{
			InstanceTypes: aws.StringSlice([]string{itype}),
		})
		if err != nil {
			return err
		}

		if len(ditOut.InstanceTypes) != 1 {
			return fmt.Errorf("describe instance-types returned %d results for %q", len(ditOut.InstanceTypes), itype)
		}

		info := ditOut.InstanceTypes[0].NetworkInfo
		if *numENIs == 0 {
			*numENIs = int(aws.Int64Value(info.MaximumNetworkInterfaces))
		}
		if *numIPs == 0 {
			*numIPs = int(aws.Int64Value(info.Ipv4AddressesPerInterface))
		}
		log.Printf("Using --enis=%d --ips=%d", *numENIs, *numIPs)
	}

	// Add to existing ENIs if possible
	for _, mac := range devNums {
		if availableIPs >= *maxIPs {
			// Good enough!
			break
		}

		ips, err := imds.GetLocalIPv4s(ctx, mac)
		if err != nil {
			return err
		}

		if len(ips) < *numIPs {
			// Existing interface needs more IPs.
			interfaceID, err := imds.GetInterfaceID(ctx, mac)
			if err != nil {
				return err
			}

			log.Printf("Assigning %d additional IPs to %s", *numIPs-len(ips), mac)

			_, err = ec2Svc.AssignPrivateIpAddressesWithContext(ctx, &ec2.AssignPrivateIpAddressesInput{
				NetworkInterfaceId:             aws.String(interfaceID),
				SecondaryPrivateIpAddressCount: aws.Int64(int64(*numIPs - len(ips))),
			})
			if err != nil {
				return err
			}

			availableIPs += *numIPs - len(ips)
		}
	}

	// Create+attach new ENIs up to numENIs
	for devNum := 0; len(devNums) < *numENIs; devNum++ {
		if availableIPs >= *maxIPs {
			// Good enough!
			break
		}

		if _, ok := devNums[devNum]; ok {
			// This devNum already exists
			continue
		}

		log.Printf("Creating additional ENI with %d secondary IPs", *numIPs-1)
		cniOut, err := ec2Svc.CreateNetworkInterfaceWithContext(ctx, &ec2.CreateNetworkInterfaceInput{
			Description:                    aws.String(fmt.Sprintf("ENI for %s", instanceID)),
			Groups:                         aws.StringSlice(sgIDs),
			SubnetId:                       aws.String(subnetID),
			SecondaryPrivateIpAddressCount: aws.Int64(int64(*numIPs - 1)),
		})
		if err != nil {
			return err
		}
		interfaceID := aws.StringValue(cniOut.NetworkInterface.NetworkInterfaceId)

		cleanupENI := func(id, aid *string) {
			// Best-effort cleanup.  No error checking, no context.
			if aid != nil {
				log.Printf("Attempting to detach ENI %s", *id)
				ec2Svc.DetachNetworkInterface(&ec2.DetachNetworkInterfaceInput{
					AttachmentId: aid,
				})
			}
			log.Printf("Attempting to delete ENI %s", *id)
			ec2Svc.DeleteNetworkInterface(&ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: id,
			})
		}

		log.Printf("Attaching new ENI %s to index %d", interfaceID, devNum)
		aniOut, err := ec2Svc.AttachNetworkInterfaceWithContext(ctx, &ec2.AttachNetworkInterfaceInput{
			DeviceIndex:        aws.Int64(int64(devNum)),
			InstanceId:         aws.String(instanceID),
			NetworkInterfaceId: aws.String(interfaceID),
		})
		if err != nil {
			cleanupENI(aws.String(interfaceID), nil)
			return err
		}

		log.Printf("Setting DeleteOnTermination on interface %s attachment %s", interfaceID, aws.StringValue(aniOut.AttachmentId))
		_, err = ec2Svc.ModifyNetworkInterfaceAttributeWithContext(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: aws.String(interfaceID),
			Attachment: &ec2.NetworkInterfaceAttachmentChanges{
				AttachmentId:        aniOut.AttachmentId,
				DeleteOnTermination: aws.Bool(true),
			},
		})
		if err != nil {
			cleanupENI(aws.String(interfaceID), aniOut.AttachmentId)
			return err
		}

		devNums[devNum] = aws.StringValue(cniOut.NetworkInterface.MacAddress)
		availableIPs += *numIPs - 1
	}

	log.Printf("Proceeding with at least %d available IPs across %d ENIs", availableIPs, len(devNums))

	// Wait for all those interfaces+IPs to actually arrive
	waitDuration := 1 * time.Second
	for devNum, mac := range devNums {
		for {
			ips, err := imds.GetLocalIPv4s(ctx, mac)
			if err == nil && len(ips) >= *numIPs {
				// Ready to go!
				break
			}
			if err != nil && !awsutils.IsNotFound(err) {
				return err
			}

			log.Printf("Waiting %s for interface %s (device-index %d) to report %d IPs in IMDS", waitDuration, mac, devNum, *numIPs)
			time.Sleep(waitDuration)

			// Arbitrary geometric increase
			waitDuration = time.Duration(float64(waitDuration) * 1.4)

			// Invalidate IMDS cache
			imds = awsutils.TypedIMDS{awsutils.NewCachedIMDS(ec2Metadata)}
		}
	}

	return nil
}
