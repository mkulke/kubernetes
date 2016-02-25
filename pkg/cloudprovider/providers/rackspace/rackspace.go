/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rackspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/rackspace/gophercloud/openstack/compute/v2/extensions/volumeattach"
	osservers "github.com/rackspace/gophercloud/openstack/compute/v2/servers"
	"github.com/rackspace/gophercloud/pagination"
	"github.com/rackspace/gophercloud/rackspace"
	"github.com/rackspace/gophercloud/rackspace/compute/v2/servers"
	"github.com/scalingdata/gcfg"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/cloudprovider"
)

const ProviderName = "rackspace"
const metaDataPath = "/media/configdrive/openstack/latest/meta_data.json"

var ErrNotFound = errors.New("Failed to find object")
var ErrMultipleResults = errors.New("Multiple results where only one expected")
var ErrNoAddressFound = errors.New("No address found for host")
var ErrAttrNotFound = errors.New("Expected attribute not found")

// encoding.TextUnmarshaler interface for time.Duration
type MyDuration struct {
	time.Duration
}

func (d *MyDuration) UnmarshalText(text []byte) error {
	res, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = res
	return nil
}

type MetaData struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type LoadBalancerOpts struct {
	SubnetId          string     `gcfg:"subnet-id"` // required
	CreateMonitor     bool       `gcfg:"create-monitor"`
	MonitorDelay      MyDuration `gcfg:"monitor-delay"`
	MonitorTimeout    MyDuration `gcfg:"monitor-timeout"`
	MonitorMaxRetries uint       `gcfg:"monitor-max-retries"`
}

// Rackspace is an implementation of cloud provider Interface for Rackspace.
type Rackspace struct {
	provider        *gophercloud.ProviderClient
	region          string
	lbOpts          LoadBalancerOpts
	localInstanceID string
}

type Config struct {
	Global struct {
		AuthUrl    string `gcfg:"auth-url"`
		Username   string
		UserId     string `gcfg:"user-id"`
		Password   string
		ApiKey     string `gcfg:"api-key"`
		TenantId   string `gcfg:"tenant-id"`
		TenantName string `gcfg:"tenant-name"`
		DomainId   string `gcfg:"domain-id"`
		DomainName string `gcfg:"domain-name"`
		Region     string
	}
	LoadBalancer LoadBalancerOpts
}

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		cfg, err := readConfig(config)
		if err != nil {
			return nil, err
		}
		return newRackspace(cfg)
	})
}

func (cfg Config) toAuthOptions() gophercloud.AuthOptions {
	return gophercloud.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthUrl,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserId,
		Password:         cfg.Global.Password,
		APIKey:           cfg.Global.ApiKey,
		TenantID:         cfg.Global.TenantId,
		TenantName:       cfg.Global.TenantName,

		// Persistent service, so we need to be able to renew tokens
		AllowReauth: true,
	}
}

func readConfig(config io.Reader) (Config, error) {
	if config == nil {
		err := fmt.Errorf("no Rackspace cloud provider config file given")
		return Config{}, err
	}

	var cfg Config
	err := gcfg.ReadInto(&cfg, config)
	return cfg, err
}

func newRackspace(cfg Config) (*Rackspace, error) {
	provider, err := rackspace.AuthenticatedClient(cfg.toAuthOptions())
	if err != nil {
		return nil, err
	}

	id, err := readInstanceID()
	if err != nil {
		return nil, err
	}

	os := Rackspace{
		provider:        provider,
		region:          cfg.Global.Region,
		lbOpts:          cfg.LoadBalancer,
		localInstanceID: id,
	}
	return &os, nil
}

type Instances struct {
	compute *gophercloud.ServiceClient
}

// Instances returns an implementation of Instances for Rackspace.
func (os *Rackspace) Instances() (cloudprovider.Instances, bool) {
	glog.V(2).Info("rackspace.Instances() called")

	compute, err := os.getComputeClient()
	if err != nil {
		glog.Warningf("Failed to find compute endpoint: %v", err)
		return nil, false
	}
	glog.V(1).Info("Claiming to support Instances")

	return &Instances{compute}, true
}

func (i *Instances) List(name_filter string) ([]string, error) {
	glog.V(2).Infof("rackspace List(%v) called", name_filter)

	opts := osservers.ListOpts{
		Name:   name_filter,
		Status: "ACTIVE",
	}
	pager := servers.List(i.compute, opts)

	ret := make([]string, 0)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		sList, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		for _, server := range sList {
			ret = append(ret, server.Name)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	glog.V(2).Infof("Found %v entries: %v", len(ret), ret)

	return ret, nil
}

func serverHasAddress(srv osservers.Server, ip string) bool {
	if ip == firstAddr(srv.Addresses["private"]) {
		return true
	}
	if ip == firstAddr(srv.Addresses["public"]) {
		return true
	}
	if ip == srv.AccessIPv4 {
		return true
	}
	if ip == srv.AccessIPv6 {
		return true
	}
	return false
}

func getServerByAddress(client *gophercloud.ServiceClient, name string) (*osservers.Server, error) {
	pager := servers.List(client, nil)

	serverList := make([]osservers.Server, 0, 1)

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		s, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		for _, v := range s {
			if serverHasAddress(v, name) {
				serverList = append(serverList, v)
			}
		}
		if len(serverList) > 1 {
			return false, ErrMultipleResults
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if len(serverList) == 0 {
		return nil, ErrNotFound
	} else if len(serverList) > 1 {
		return nil, ErrMultipleResults
	}

	return &serverList[0], nil
}

func getServerByName(client *gophercloud.ServiceClient, name string) (*osservers.Server, error) {
	if net.ParseIP(name) != nil {
		// we're an IP, so we'll have to walk the full list of servers to
		// figure out which one we are.
		return getServerByAddress(client, name)
	}
	opts := osservers.ListOpts{
		Name:   fmt.Sprintf("^%s$", regexp.QuoteMeta(name)),
		Status: "ACTIVE",
	}
	pager := servers.List(client, opts)

	serverList := make([]osservers.Server, 0, 1)

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		s, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		serverList = append(serverList, s...)
		if len(serverList) > 1 {
			return false, ErrMultipleResults
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if len(serverList) == 0 {
		return nil, ErrNotFound
	} else if len(serverList) > 1 {
		return nil, ErrMultipleResults
	}

	return &serverList[0], nil
}

func firstAddr(netblob interface{}) string {
	// Run-time types for the win :(
	list, ok := netblob.([]interface{})
	if !ok || len(list) < 1 {
		return ""
	}
	props, ok := list[0].(map[string]interface{})
	if !ok {
		return ""
	}
	tmp, ok := props["addr"]
	if !ok {
		return ""
	}
	addr, ok := tmp.(string)
	if !ok {
		return ""
	}
	return addr
}

func getAddressByName(api *gophercloud.ServiceClient, name string) (string, error) {
	srv, err := getServerByName(api, name)
	if err != nil {
		return "", err
	}

	var s string
	if s == "" {
		s = firstAddr(srv.Addresses["private"])
	}
	if s == "" {
		s = firstAddr(srv.Addresses["public"])
	}
	if s == "" {
		s = srv.AccessIPv4
	}
	if s == "" {
		s = srv.AccessIPv6
	}
	if s == "" {
		return "", ErrNoAddressFound
	}
	return s, nil
}

func (i *Instances) NodeAddresses(name string) ([]api.NodeAddress, error) {
	glog.V(2).Infof("NodeAddresses(%v) called", name)

	ip, err := getAddressByName(i.compute, name)
	if err != nil {
		return nil, err
	}

	glog.V(2).Infof("NodeAddresses(%v) => %v", name, ip)

	// net.ParseIP().String() is to maintain compatibility with the old code
	return []api.NodeAddress{{Type: api.NodeLegacyHostIP, Address: net.ParseIP(ip).String()}}, nil
}

func readInstanceID() (string, error) {
	metaDataBytes, err := ioutil.ReadFile(metaDataPath)
	if err != nil {
		return "", fmt.Errorf("Cannot read %s: %v", metaDataPath, err)
	}

	metaData := MetaData{}
	err = json.Unmarshal(metaDataBytes, &metaData)
	if err != nil {
		return "", fmt.Errorf("Cannot parse %s: %v", metaDataPath, err)
	}

	return metaData.UUID, nil
}

// ExternalID returns the cloud provider ID of the specified instance (deprecated).
func (i *Instances) ExternalID(name string) (string, error) {
	return readInstanceID()
}

// InstanceID returns the cloud provider ID of the specified instance.
func (i *Instances) InstanceID(name string) (string, error) {
	return readInstanceID()
}

// InstanceType returns the type of the specified instance.
func (i *Instances) InstanceType(name string) (string, error) {
	return "", nil
}

func (i *Instances) AddSSHKeyToAllInstances(user string, keyData []byte) error {
	return errors.New("unimplemented")
}

// Implementation of Instances.CurrentNodeName
func (i *Instances) CurrentNodeName(hostname string) (string, error) {
	return hostname, nil
}

func (os *Rackspace) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// ProviderName returns the cloud provider ID.
func (os *Rackspace) ProviderName() string {
	return ProviderName
}

// ScrubDNS filters DNS settings for pods.
func (os *Rackspace) ScrubDNS(nameservers, searches []string) (nsOut, srchOut []string) {
	return nameservers, searches
}

func (os *Rackspace) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return nil, false
}

func (os *Rackspace) Zones() (cloudprovider.Zones, bool) {
	glog.V(1).Info("Claiming to support Zones")

	return os, true
}

func (os *Rackspace) Routes() (cloudprovider.Routes, bool) {
	return nil, false
}

func (os *Rackspace) GetZone() (cloudprovider.Zone, error) {
	glog.V(1).Infof("Current zone is %v", os.region)

	return cloudprovider.Zone{Region: os.region}, nil
}

// Create a volume of given size (in GiB)
func (os *Rackspace) CreateVolume(name string, size int, tags *map[string]string) (volumeName string, err error) {
	return "", errors.New("unimplemented")
}

func (os *Rackspace) DeleteVolume(volumeName string) error {
	return errors.New("unimplemented")
}

// Attaches given cinder volume to the compute running kubelet
func (os *Rackspace) AttachDisk(diskName string) (string, error) {
	disk, err := os.getVolume(diskName)
	if err != nil {
		return "", err
	}

	compute, err := os.getComputeClient()
	if err != nil {
		return "", err
	}

	if len(disk.Attachments) > 0 && disk.Attachments[0]["server_id"] != nil {
		if os.localInstanceID == disk.Attachments[0]["server_id"] {
			glog.V(4).Infof("Disk: %q is already attached to compute: %q", diskName, os.localInstanceID)
			return disk.ID, nil
		} else {
			errMsg := fmt.Sprintf("Disk %q is attached to a different compute: %q, should be detached before proceeding", diskName, disk.Attachments[0]["server_id"])
			glog.Errorf(errMsg)
			return "", errors.New(errMsg)
		}
	}

	_, err = volumeattach.Create(compute, os.localInstanceID, &volumeattach.CreateOpts{
		VolumeID: disk.ID,
	}).Extract()
	if err != nil {
		glog.Errorf("Failed to attach %s volume to %s compute", diskName, os.localInstanceID)
		return "", err
	}
	glog.V(2).Infof("Successfully attached %s volume to %s compute", diskName, os.localInstanceID)
	return disk.ID, nil
}

func (os *Rackspace) GetDevicePath(diskId string) string {
	volume, err := os.getVolume(diskId)
	if err != nil {
		return ""
	}
	attachments := volume.Attachments
	if len(attachments) != 1 {
		glog.Warningf("Unexpected number of volume attachements on %s: %d", diskId, len(attachments))
		return ""
	}
	return attachments[0]["device"].(string)
}

// Takes a partial/full disk id or diskname
func (os *Rackspace) getVolume(diskName string) (volumes.Volume, error) {
	sClient, err := rackspace.NewBlockStorageV1(os.provider, gophercloud.EndpointOpts{
		Region: os.region,
	})

	var volume volumes.Volume
	if err != nil || sClient == nil {
		glog.Errorf("Unable to initialize cinder client for region: %s", os.region)
		return volume, err
	}

	err = volumes.List(sClient, nil).EachPage(func(page pagination.Page) (bool, error) {
		vols, err := volumes.ExtractVolumes(page)
		if err != nil {
			glog.Errorf("Failed to extract volumes: %v", err)
			return false, err
		} else {
			for _, v := range vols {
				glog.V(4).Infof("%s %s %v", v.ID, v.Name, v.Attachments)
				if v.Name == diskName || strings.Contains(v.ID, diskName) {
					volume = v
					return true, nil
				}
			}
		}
		// if it reached here then no disk with the given name was found.
		errmsg := fmt.Sprintf("Unable to find disk: %s in region %s", diskName, os.region)
		return false, errors.New(errmsg)
	})
	if err != nil {
		glog.Errorf("Error occured getting volume: %s", diskName)
		return volume, err
	}
	return volume, err
}

func (os *Rackspace) getComputeClient() (*gophercloud.ServiceClient, error) {
	client, err := rackspace.NewComputeV2(os.provider, gophercloud.EndpointOpts{
		Region: os.region,
	})
	if err != nil || client == nil {
		glog.Errorf("Unable to initialize nova client for region: %s", os.region)
		return nil, err
	}
	return client, nil
}

// Detaches given cinder volume from the compute running kubelet
func (os *Rackspace) DetachDisk(partialDiskId string) error {
	disk, err := os.getVolume(partialDiskId)
	if err != nil {
		return err
	}

	compute, err := os.getComputeClient()
	if err != nil {
		return err
	}

	if len(disk.Attachments) > 0 && disk.Attachments[0]["server_id"] != nil && os.localInstanceID == disk.Attachments[0]["server_id"] {
		// This is a blocking call and effects kubelet's performance directly.
		// We should consider kicking it out into a separate routine, if it is bad.
		err = volumeattach.Delete(compute, os.localInstanceID, disk.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Failed to delete volume %s from compute %s attached %v", disk.ID, os.localInstanceID, err)
			return err
		}
		glog.V(2).Infof("Successfully detached volume: %s from compute: %s", disk.ID, os.localInstanceID)
	} else {
		errMsg := fmt.Sprintf("Disk: %s has no attachments or is not attached to compute: %s", disk.Name, os.localInstanceID)
		glog.Errorf(errMsg)
		return errors.New(errMsg)
	}
	return nil
}
