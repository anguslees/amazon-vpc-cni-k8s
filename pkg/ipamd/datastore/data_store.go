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

package datastore

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/cri"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// minENILifeTime is the shortest time before we consider deleting a newly created ENI
	minENILifeTime = 1 * time.Minute

	// addressCoolingPeriod is used to ensure an IP not get assigned to a Pod if this IP is used by a different Pod
	// in addressCoolingPeriod
	addressCoolingPeriod = 30 * time.Second

	// DuplicatedENIError is an error when caller tries to add an duplicate ENI to data store
	DuplicatedENIError = "data store: duplicate ENI"

	// IPAlreadyInStoreError is an error when caller tries to add an duplicate IP address to data store
	IPAlreadyInStoreError = "datastore: IP already in data store"

	// UnknownIPError is an error when caller tries to delete an IP which is unknown to data store
	UnknownIPError = "datastore: unknown IP"

	// IPInUseError is an error when caller tries to delete an IP where IP is still assigned to a Pod
	IPInUseError = "datastore: IP is used and can not be deleted"

	// ENIInUseError is an error when caller tries to delete an ENI where there are IP still assigned to a pod
	ENIInUseError = "datastore: ENI is used and can not be deleted"

	// UnknownENIError is an error when caller tries to access an ENI which is unknown to datastore
	UnknownENIError = "datastore: unknown ENI"
)

// Enable temporary checkpoint upgrade logic.  If checkpoint file is
// not found, query CRI to learn current pods and currently-allocated
// IPs.  Will be disabled/removed after next release.
const BackfillMissingCheckpointFromCRI = true
const BackfillNetworkName = "_migrated-from-cri"
const BackfillNetworkIface = "unknown"

// ErrUnknownPod is an error when there is no pod in data store matching pod name, namespace, sandbox id
var ErrUnknownPod = errors.New("datastore: unknown pod")

var (
	enis = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "awscni_eni_allocated",
			Help: "The number of ENIs allocated",
		},
	)
	totalIPs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "awscni_total_ip_addresses",
			Help: "The total number of IP addresses",
		},
	)
	assignedIPs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "awscni_assigned_ip_addresses",
			Help: "The number of IP addresses assigned to pods",
		},
	)
	forceRemovedENIs = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "awscni_force_removed_enis",
			Help: "The number of ENIs force removed while they had assigned pods",
		},
	)
	forceRemovedIPs = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "awscni_force_removed_ips",
			Help: "The number of IPs force removed while they had assigned pods",
		},
	)
	prometheusRegistered = false
)

// IPAMKey is the IPAM primary key.  Quoting CNI spec:
//   Plugins that store state should do so using a primary key of
//   (network name, CNI_CONTAINERID, CNI_IFNAME).
type IPAMKey struct {
	NetworkName string `json:"networkName"`
	ContainerID string `json:"containerID"`
	IfName      string `json:"ifName"`
}

// IsZero returns true iff object is equal to the golang zero/null value.
func (k IPAMKey) IsZero() bool {
	return k == IPAMKey{}
}

// String() implements the fmt.Stringer interface.
func (k IPAMKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.NetworkName, k.ContainerID, k.IfName)
}

// ENI represents a single ENI.
type ENI struct {
	// AWS ENI ID
	ID         string
	createTime time.Time
	// IsPrimary indicates whether ENI is a primary ENI
	IsPrimary bool
	// DeviceNumber is the device number of ENI (0 means the primary ENI)
	DeviceNumber int
	// Addresses shows whether each address is assigned, order is not significant
	Addresses []*AddressInfo
}

// AddressInfo contains information about an IP, Exported fields will be marshaled for introspection.
type AddressInfo struct {
	IPAMKey        IPAMKey
	UnassignedTime time.Time
	// Note! Either of IPv4 xor IPv6 address might be "", if the
	// cluster is IPv4-only or IPv6-only.
	// Note also: we always allocate/free addresses in pairs (in a
	// dual-stack cluster)
	IPv4Address string
	IPv6Address string
}

// Remove an address from the Addresses list and return it.  It is not
// safe to continue iterating over the Addresses list (the list will
// be reordered).
func (e *ENI) removeAddress(idx int) *AddressInfo {
	ret := e.Addresses[idx]
	// Replace with last element
	e.Addresses[idx] = e.Addresses[len(e.Addresses)-1]
	e.Addresses = e.Addresses[:len(e.Addresses)-1]
	return ret
}

func (e *ENI) findAddressForSandbox(ipamKey IPAMKey) *AddressInfo {
	for _, addr := range e.Addresses {
		if addr.IPAMKey == ipamKey {
			return addr
		}
	}
	return nil
}

// AssignedAddresses is the number of IP address (pairs) already assigned
func (e *ENI) AssignedAddresses() int {
	count := 0
	for _, addr := range e.Addresses {
		if addr.Assigned() {
			count++
		}
	}
	return count
}

// Assigned returns true iff the address is allocated to a pod/sandbox.
func (addr AddressInfo) Assigned() bool {
	return !addr.IPAMKey.IsZero()
}

// InCoolingPeriod checks whether an addr is in addressCoolingPeriod
func (addr AddressInfo) inCoolingPeriod() bool {
	return time.Since(addr.UnassignedTime) <= addressCoolingPeriod
}

// ENIPool is a collection of ENI, keyed by ENI ID
type ENIPool map[string]*ENI

// AssignedAddresses is the number of IP address (pairs) already assigned
func (p *ENIPool) AssignedAddresses() int {
	count := 0
	for _, eni := range *p {
		count += eni.AssignedAddresses()
	}
	return count
}

// FindAddressForSandbox returns ENI and AddressInfo or (nil, nil) if not found
func (p *ENIPool) FindAddressForSandbox(ipamKey IPAMKey) (*ENI, *AddressInfo) {
	for _, eni := range *p {
		if addr := eni.findAddressForSandbox(ipamKey); addr != nil {
			return eni, addr
		}
	}
	return nil, nil
}

// PodIPInfo contains pod's IP and the device number of the ENI
type PodIPInfo struct {
	IPAMKey IPAMKey
	// IPv4 is the IPv4 address of pod (or "" for IPv6-only)
	IPv4 string
	// IPv6 is the IPv6 address of pod (or "" for IPv4-only)
	IPv6 string
	// DeviceNumber is the device number of the ENI
	DeviceNumber int
}

// Assigned returns true iff the address is allocated to a pod/sandbox.
func (p PodIPInfo) Assigned() bool {
	return !p.IPAMKey.IsZero()
}

// DataStore contains node level ENI/IP
type DataStore struct {
	total        int
	assigned     int
	eniPool      ENIPool
	assignIPv4   bool
	assignIPv6   bool
	lock         sync.Mutex
	log          logger.Logger
	backingStore Checkpointer
	cri          cri.APIs
}

// ENIInfos contains ENI IP information
type ENIInfos struct {
	// TotalIPs is the total number of IP addresses
	TotalIPs int
	// assigned is the number of IP addresses that has been assigned
	AssignedIPs int
	// ENIs contains ENI IP pool information
	ENIs map[string]ENI
}

func prometheusRegister() {
	if !prometheusRegistered {
		prometheus.MustRegister(enis)
		prometheus.MustRegister(totalIPs)
		prometheus.MustRegister(assignedIPs)
		prometheus.MustRegister(forceRemovedENIs)
		prometheus.MustRegister(forceRemovedIPs)
		prometheusRegistered = true
	}
}

// NewDataStore returns DataStore structure
func NewDataStore(log logger.Logger, backingStore Checkpointer) *DataStore {
	prometheusRegister()
	return &DataStore{
		eniPool:      make(ENIPool),
		log:          log,
		backingStore: backingStore,
		cri:          cri.New(),
	}
}

// CheckpointFormatVersion is the version stamp used on stored checkpoints.
const CheckpointFormatVersion = "vpc-cni-ipam/1"

// CheckpointData is the format of stored checkpoints. Note this is
// deliberately a "dumb" format since efficiency is less important
// than version stability here.
type CheckpointData struct {
	Version     string            `json:"version"`
	Allocations []CheckpointEntry `json:"allocations"`
}

// CheckpointEntry is a "row" in the conceptual IPAM datastore, as stored
// in checkpoints.
type CheckpointEntry struct {
	IPAMKey
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

// ReadBackingStore initialises the IP allocation state from the
// configured backing store.  Should be called before using data
// store.
func (ds *DataStore) ReadBackingStore() error {
	ds.log.Infof("Reading ipam state from backing store")

	var data CheckpointData
	err := ds.backingStore.Restore(&data)
	ds.log.Debugf("backing store restore returned err %v", err)
	if BackfillMissingCheckpointFromCRI && os.IsNotExist(err) {
		ds.log.Infof("Backing store not found. Querying CRI.")
		sandboxes, err := ds.cri.GetRunningPodSandboxes(ds.log)
		if err != nil {
			return err
		}

		entries := make([]CheckpointEntry, 0, len(sandboxes))
		for _, s := range sandboxes {
			entries = append(entries, CheckpointEntry{
				// NB: These Backfill values are also assumed in UnassignPodIPv4Address
				IPAMKey: IPAMKey{
					NetworkName: BackfillNetworkName,
					ContainerID: s.ID,
					IfName:      BackfillNetworkIface,
				},
				IPv4: s.IP,
			})
		}
		data = CheckpointData{
			Version:     CheckpointFormatVersion,
			Allocations: entries,
		}

	} else if os.IsNotExist(err) {
		// Assume that no file == no containers are
		// currently in use, eg a fresh reboot just
		// cleared everything out.  This is ok, and a
		// no-op.
		return nil
	} else if err != nil {
		return fmt.Errorf("datastore: error reading backing store: %v", err)
	}

	if data.Version != CheckpointFormatVersion {
		return fmt.Errorf("datastore: unknown backing store format (%s != %s) - wrong CNI/ipamd version? (Rebooting this node will restart local pods and probably help)", data.Version, CheckpointFormatVersion)
	}

	ds.lock.Lock()
	defer ds.lock.Unlock()

	// This is a bit cumbersome, but we need to find and then
	// verify the v4 and v6 addresses *both* match (if present).
	type ENIAddr struct {
		eni  *ENI
		addr *AddressInfo
	}
	eniIPs := make(map[string]*ENIAddr)
	for _, eni := range ds.eniPool {
		for _, addr := range eni.Addresses {
			parent := ENIAddr{eni: eni, addr: addr}
			eniIPs[addr.IPv4Address] = &parent
			eniIPs[addr.IPv6Address] = &parent
		}
	}

	for _, allocation := range data.Allocations {
		var eniAddr *ENIAddr
		switch {
		case allocation.IPv4 != "":
			eniAddr = eniIPs[allocation.IPv4]
		case allocation.IPv6 != "":
			eniAddr = eniIPs[allocation.IPv6]
		default:
			ds.log.Debugf("datastore: Ignoring checkpoint entry without IPv4 or IPv6 address. (%v)", allocation)
			continue
		}

		if eniAddr == nil {
			ds.log.Infof("datastore: Sandbox %s uses unknown IP - presuming stale/dead", allocation.IPAMKey)
			continue
		}

		eni := eniAddr.eni
		addr := eniAddr.addr

		if addr.IPv4Address != allocation.IPv4 {
			ds.log.Infof("datastore: Checkpoint for %s doesn't match ENI IPv4 address (%s != %s), assuming stale/dead.", allocation.IPAMKey, addr.IPv4Address, allocation.IPv4)
			continue
		}
		if addr.IPv6Address != allocation.IPv6 {
			ds.log.Infof("datastore: Checkpoint for %s doesn't match ENI IPv6 address (%s != %s), assuming stale/dead.", allocation.IPAMKey, addr.IPv6Address, allocation.IPv6)
			continue
		}

		ds.assignPodAddressUnsafe(allocation.IPAMKey, eni, addr)
		ds.log.Debugf("Recovered %s => %s/%s/%s", allocation.IPAMKey, eni.ID, addr.IPv4Address, addr.IPv6Address)
	}

	ds.log.Debugf("Completed reading ipam state from backing store")
	return nil
}

func (ds *DataStore) writeBackingStoreUnsafe() error {
	allocations := make([]CheckpointEntry, 0, ds.assigned)

	for _, eni := range ds.eniPool {
		for _, addr := range eni.Addresses {
			if addr.Assigned() {
				entry := CheckpointEntry{
					IPAMKey: addr.IPAMKey,
					IPv4:    addr.IPv4Address,
					IPv6:    addr.IPv6Address,
				}
				allocations = append(allocations, entry)
			}
		}
	}

	data := CheckpointData{
		Version:     CheckpointFormatVersion,
		Allocations: allocations,
	}

	return ds.backingStore.Checkpoint(&data)
}

// AddENI add ENI to data store
func (ds *DataStore) AddENI(eniID string, deviceNumber int, isPrimary bool) error {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.log.Debugf("DataStore Add an ENI %s", eniID)

	_, ok := ds.eniPool[eniID]
	if ok {
		return errors.New(DuplicatedENIError)
	}
	ds.eniPool[eniID] = &ENI{
		createTime:   time.Now(),
		IsPrimary:    isPrimary,
		ID:           eniID,
		DeviceNumber: deviceNumber,
	}
	enis.Set(float64(len(ds.eniPool)))
	return nil
}

// AddAddressToStore add IPv4/IPv6 of an ENI to data store
func (ds *DataStore) AddAddressToStore(eniID, ipv4, ipv6 string) error {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	curENI, ok := ds.eniPool[eniID]
	if !ok {
		return errors.New("add ENI's IP to datastore: unknown ENI")
	}

	// Already there?
	for _, addr := range curENI.Addresses {
		if (ipv4 != "" && addr.IPv4Address == ipv4) || (ipv6 != "" && addr.IPv6Address == ipv6) {
			return errors.New(IPAlreadyInStoreError)
		}
	}

	ds.total++
	// Prometheus gauge
	totalIPs.Set(float64(ds.total))

	addr := AddressInfo{IPv4Address: ipv4, IPv6Address: ipv6}
	curENI.Addresses = append(curENI.Addresses, &addr)
	ds.log.Infof("Added ENI(%s)'s IP %s,%s to datastore", eniID, ipv4, ipv6)
	return nil
}

// DelAddressFromStore deletes IPv4/IPv6 of ENI from datastore
func (ds *DataStore) DelAddressFromStore(eniID, ipv4, ipv6 string, force bool) error {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	curENI, ok := ds.eniPool[eniID]
	if !ok {
		return errors.New(UnknownENIError)
	}

	var addr *AddressInfo
	var idx int
	for i, a := range curENI.Addresses {
		if (ipv4 != "" && a.IPv4Address == ipv4) || (ipv6 != "" && a.IPv6Address == ipv6) {
			idx = i
			addr = a
			break
		}
	}
	if addr == nil {
		return errors.New(UnknownIPError)
	}

	if addr.Assigned() {
		if !force {
			return errors.New(IPInUseError)
		}
		ds.log.Warnf("Force deleting assigned ip %s on eni %s", ipv4, eniID)
		forceRemovedIPs.Inc()
		ds.unassignPodAddressUnsafe(curENI, addr)
		if err := ds.writeBackingStoreUnsafe(); err != nil {
			ds.log.Warnf("Unable to update backing store: %v", err)
			// Continuing because 'force'
		}
	}

	ds.total--
	// Prometheus gauge
	totalIPs.Set(float64(ds.total))

	curENI.removeAddress(idx)

	ds.log.Infof("Deleted ENI(%s)'s IP %s,%s from datastore", eniID, ipv4, ipv6)
	return nil
}

// AssignPodAddress assigns an IP address to pod.
// It returns the assigned IPv4, IPv6 address, device number, error.
// Note one (but not both!) of the addresses may be "".
func (ds *DataStore) AssignPodAddress(ipamKey IPAMKey) (string, string, int, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.log.Debugf("AssignIPAddress: IP address pool stats: total: %d, assigned %d", ds.total, ds.assigned)
	if eni, addr := ds.eniPool.FindAddressForSandbox(ipamKey); addr != nil {
		ds.log.Infof("AssignPodAddress: duplicate pod assign for sandbox %s", ipamKey)
		return addr.IPv4Address, addr.IPv6Address, eni.DeviceNumber, nil
	}

	for _, eni := range ds.eniPool {
		for _, addr := range eni.Addresses {
			if !addr.Assigned() && !addr.inCoolingPeriod() {
				ip4, ip6, num := ds.assignPodAddressUnsafe(ipamKey, eni, addr)
				if err := ds.writeBackingStoreUnsafe(); err != nil {
					ds.log.Warnf("Failed to update backing store: %v", err)
					// Important! Unwind assignment
					ds.unassignPodAddressUnsafe(eni, addr)
					return "", "", 0, err
				}

				return ip4, ip6, num, nil
			}
		}
		ds.log.Debugf("AssignPodAddress: ENI %s does not have available addresses", eni.ID)
	}
	ds.log.Errorf("DataStore has no available IP addresses")
	return "", "", 0, errors.New("AssignPodAddress: no available IP addresses")
}

// It returns the assigned IPv4, IPv6 address, device number
func (ds *DataStore) assignPodAddressUnsafe(ipamKey IPAMKey, eni *ENI, addr *AddressInfo) (string, string, int) {
	ds.log.Infof("AssignPodAddress: Assign IP %s,%s to sandbox %s",
		addr.IPv4Address, addr.IPv6Address, ipamKey)

	if addr.Assigned() {
		// If we're double-assigning then something has gone very wrong.
		panic("addr already assigned")
	}
	addr.IPAMKey = ipamKey // This marks the addr as assigned

	ds.assigned++
	// Prometheus gauge
	assignedIPs.Set(float64(ds.assigned))

	return addr.IPv4Address, addr.IPv6Address, eni.DeviceNumber
}

func (ds *DataStore) unassignPodAddressUnsafe(eni *ENI, addr *AddressInfo) {
	if !addr.Assigned() {
		// Already unassigned
		return
	}
	ds.log.Infof("unassignPodAddress: Unassign IP %s,%s from sandbox %s",
		addr.IPv4Address, addr.IPv6Address, addr.IPAMKey)
	addr.IPAMKey = IPAMKey{} // unassign the addr
	ds.assigned--
	// Prometheus gauge
	assignedIPs.Set(float64(ds.assigned))
}

// GetStats returns total number of IP addresses and number of assigned IP addresses
func (ds *DataStore) GetStats() (int, int) {
	return ds.total, ds.assigned
}

// IsRequiredForWarmIPTarget determines if this ENI has warm IPs that are required to fulfill whatever WARM_IP_TARGET is
// set to.
func (ds *DataStore) isRequiredForWarmIPTarget(warmIPTarget int, eni *ENI) bool {
	otherWarmIPs := 0
	for _, other := range ds.eniPool {
		if other.ID != eni.ID {
			otherWarmIPs += len(other.Addresses) - other.AssignedAddresses()
		}
	}
	return otherWarmIPs < warmIPTarget
}

// IsRequiredForMinimumIPTarget determines if this ENI is necessary to fulfill whatever MINIMUM_IP_TARGET is
// set to.
func (ds *DataStore) isRequiredForMinimumIPTarget(minimumIPTarget int, eni *ENI) bool {
	otherIPs := 0
	for _, other := range ds.eniPool {
		if other.ID != eni.ID {
			otherIPs += len(other.Addresses)
		}
	}
	return otherIPs < minimumIPTarget
}

func (ds *DataStore) getDeletableENI(warmIPTarget int, minimumIPTarget int) *ENI {
	for _, eni := range ds.eniPool {
		if eni.IsPrimary {
			ds.log.Debugf("ENI %s cannot be deleted because it is primary", eni.ID)
			continue
		}

		if eni.isTooYoung() {
			ds.log.Debugf("ENI %s cannot be deleted because it is too young", eni.ID)
			continue
		}

		if eni.hasIPInCooling() {
			ds.log.Debugf("ENI %s cannot be deleted because has IPs in cooling", eni.ID)
			continue
		}

		if eni.hasPods() {
			ds.log.Debugf("ENI %s cannot be deleted because it has pods assigned", eni.ID)
			continue
		}

		if warmIPTarget != 0 && ds.isRequiredForWarmIPTarget(warmIPTarget, eni) {
			ds.log.Debugf("ENI %s cannot be deleted because it is required for WARM_IP_TARGET: %d", eni.ID, warmIPTarget)
			continue
		}

		if minimumIPTarget != 0 && ds.isRequiredForMinimumIPTarget(minimumIPTarget, eni) {
			ds.log.Debugf("ENI %s cannot be deleted because it is required for MINIMUM_IP_TARGET: %d", eni.ID, minimumIPTarget)
			continue
		}

		ds.log.Debugf("getDeletableENI: found a deletable ENI %s", eni.ID)
		return eni
	}
	return nil
}

// IsTooYoung returns true if the ENI hasn't been around long enough to be deleted.
func (e *ENI) isTooYoung() bool {
	return time.Since(e.createTime) < minENILifeTime
}

// HasIPInCooling returns true if an IP address was unassigned recently.
func (e *ENI) hasIPInCooling() bool {
	for _, addr := range e.Addresses {
		if addr.inCoolingPeriod() {
			return true
		}
	}
	return false
}

// HasPods returns true if the ENI has pods assigned to it.
func (e *ENI) hasPods() bool {
	return e.AssignedAddresses() != 0
}

// GetENINeedsIP finds an ENI in the datastore that needs more IP addresses allocated
func (ds *DataStore) GetENINeedsIP(maxIPperENI int, skipPrimary bool) (string, int) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	for _, eni := range ds.eniPool {
		if skipPrimary && eni.IsPrimary {
			ds.log.Debugf("Skip the primary ENI for need IP check")
			continue
		}
		if len(eni.Addresses) < maxIPperENI {
			ds.log.Debugf("Found ENI %s that has less than the maximum number of IP addresses allocated: cur=%d, max=%d",
				eni.ID, len(eni.Addresses), maxIPperENI)
			return eni.ID, len(eni.Addresses)
		}
	}
	return "", 0
}

// RemoveUnusedENIFromStore removes a deletable ENI from the data store.
// It returns the name of the ENI which has been removed from the data store and needs to be deleted,
// or empty string if no ENI could be removed.
func (ds *DataStore) RemoveUnusedENIFromStore(warmIPTarget int, minimumIPTarget int) string {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	deletableENI := ds.getDeletableENI(warmIPTarget, minimumIPTarget)
	if deletableENI == nil {
		return ""
	}

	removableENI := deletableENI.ID
	eniIPCount := len(ds.eniPool[removableENI].Addresses)
	ds.total -= eniIPCount
	ds.log.Infof("RemoveUnusedENIFromStore %s: IP address pool stats: free %d addresses, total: %d, assigned: %d",
		removableENI, eniIPCount, ds.total, ds.assigned)
	delete(ds.eniPool, removableENI)

	// Prometheus update
	enis.Set(float64(len(ds.eniPool)))
	totalIPs.Set(float64(ds.total))
	return removableENI
}

// RemoveENIFromDataStore removes an ENI from the datastore.  It return nil on success or an error.
func (ds *DataStore) RemoveENIFromDataStore(eniID string, force bool) error {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	eni, ok := ds.eniPool[eniID]
	if !ok {
		return errors.New(UnknownENIError)
	}

	if eni.hasPods() {
		if !force {
			return errors.New(ENIInUseError)
		}
		// This scenario can occur if the reconciliation process discovered this eni was detached
		// from the EC2 instance outside of the control of ipamd.  If this happens, there's nothing
		// we can do other than force all pods to be unassigned from the IPs on this eni.
		ds.log.Warnf("Force removing eni %s with %d assigned pods", eniID, eni.AssignedAddresses())
		forceRemovedENIs.Inc()
		forceRemovedIPs.Add(float64(eni.AssignedAddresses()))
		for _, addr := range eni.Addresses {
			if addr.Assigned() {
				ds.unassignPodAddressUnsafe(eni, addr)
			}
		}
		if err := ds.writeBackingStoreUnsafe(); err != nil {
			ds.log.Warnf("Unable to update backing store: %v", err)
			// Continuing, because 'force'
		}
	}

	ds.total -= len(eni.Addresses)
	ds.log.Infof("RemoveENIFromDataStore %s: IP address pool stats: free %d addresses, total: %d, assigned: %d",
		eni, len(eni.Addresses), ds.total, ds.assigned)
	delete(ds.eniPool, eniID)

	// Prometheus gauge
	enis.Set(float64(len(ds.eniPool)))
	return nil
}

// UnassignPodAddress a) find out the IP address based on ipamKey
// b)  mark IP address as unassigned c) returns IPv4+IPv6 address, ENI's device number, error
func (ds *DataStore) UnassignPodAddress(ipamKey IPAMKey) (string, string, int, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.log.Debugf("UnassignPodAddress: IP address pool stats: total:%d, assigned %d, sandbox %s",
		ds.total, ds.assigned, ipamKey)

	eni, addr := ds.eniPool.FindAddressForSandbox(ipamKey)

	if BackfillMissingCheckpointFromCRI && addr == nil {
		ds.log.Debugf("UnassignPodAddress: Failed to find IPAM entry under full key, trying CRI-migrated version")
		ipamKey.NetworkName = BackfillNetworkName
		ipamKey.IfName = BackfillNetworkIface
		eni, addr = ds.eniPool.FindAddressForSandbox(ipamKey)
	}
	if addr == nil {
		ds.log.Warnf("UnassignPodAddress: Failed to find sandbox %s",
			ipamKey)
		return "", "", 0, ErrUnknownPod
	}

	ds.unassignPodAddressUnsafe(eni, addr)
	if err := ds.writeBackingStoreUnsafe(); err != nil {
		// Unwind un-assignment
		ds.assignPodAddressUnsafe(ipamKey, eni, addr)
		return "", "", 0, err
	}
	addr.UnassignedTime = time.Now()

	ds.log.Infof("UnassignPodAddress: sandbox %s's IPv4 %s, IPv6 %s, DeviceNumber %d",
		ipamKey, addr.IPv4Address, addr.IPv6Address, eni.DeviceNumber)
	return addr.IPv4Address, addr.IPv6Address, eni.DeviceNumber, nil
}

// GetENIInfos provides ENI IP information to introspection endpoint
func (ds *DataStore) GetENIInfos() *ENIInfos {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	var eniInfos = ENIInfos{
		TotalIPs:    ds.total,
		AssignedIPs: ds.assigned,
		ENIs:        make(map[string]ENI, len(ds.eniPool)),
	}

	for eni, eniInfo := range ds.eniPool {
		eniInfos.ENIs[eni] = *eniInfo
	}
	return &eniInfos
}

// GetENIs provides the number of ENI in the datastore
func (ds *DataStore) GetENIs() int {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	return len(ds.eniPool)
}

// GetENIIPs returns the known (allocated & unallocated) ENI IPs.
// NB: The returned data is a consistent but potentially stale
// snapshot.  This is the recommended way for external code to inspect
// the contents of the datastore (outside the datastore lock).
func (ds *DataStore) GetENIIPs() map[string][]PodIPInfo {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	// Address info arrays, grouped by ENI ID
	ret := make(map[string][]PodIPInfo)

	for _, eni := range ds.eniPool {
		addrs := make([]PodIPInfo, 0, len(eni.Addresses))
		for _, addr := range eni.Addresses {
			info := PodIPInfo{
				IPAMKey:      addr.IPAMKey,
				IPv4:         addr.IPv4Address,
				IPv6:         addr.IPv6Address,
				DeviceNumber: eni.DeviceNumber,
			}
			addrs = append(addrs, info)
		}
		ret[eni.ID] = addrs
	}

	return ret
}
