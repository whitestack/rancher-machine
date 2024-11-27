package vmwarevsphere

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/vmware/govmomi/vim25/types"
)

var (
	supportedMachineOS = map[string]struct{}{
		"windows": {},
		"linux":   {},
	}
	supportedCreationTypes = map[string]struct{}{
		creationTypeVM:      {},
		creationTypeTmpl:    {},
		creationTypeLibrary: {},
		creationTypeLegacy:  {},
	}
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_CPU_COUNT",
			Name:   "vmwarevsphere-cpu-count",
			Usage:  "vSphere CPU number for docker VM",
			Value:  defaultCpus,
		},
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_MEMORY_SIZE",
			Name:   "vmwarevsphere-memory-size",
			Usage:  "vSphere size of memory for docker VM (in MB)",
			Value:  defaultMemory,
		},
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_DISK_SIZE",
			Name:   "vmwarevsphere-disk-size",
			Usage:  "vSphere size of disk for docker VM (in MB)",
			Value:  defaultDiskSize,
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_BOOT2DOCKER_URL",
			Name:   "vmwarevsphere-boot2docker-url",
			Usage:  "vSphere URL for boot2docker image",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_VCENTER",
			Name:   "vmwarevsphere-vcenter",
			Usage:  "vSphere IP/hostname for vCenter",
		},
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_VCENTER_PORT",
			Name:   "vmwarevsphere-vcenter-port",
			Usage:  "vSphere Port for vCenter",
			Value:  defaultSDKPort,
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_USERNAME",
			Name:   "vmwarevsphere-username",
			Usage:  "vSphere username",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_PASSWORD",
			Name:   "vmwarevsphere-password",
			Usage:  "vSphere password",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "VSPHERE_NETWORK",
			Name:   "vmwarevsphere-network",
			Usage:  "vSphere network where the virtual machine will be attached",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_DATASTORE",
			Name:   "vmwarevsphere-datastore",
			Usage:  "vSphere datastore for virtual machine",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_DATASTORE_CLUSTER",
			Name:   "vmwarevsphere-datastore-cluster",
			Usage:  "vSphere datastore cluster for virtual machine",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_DATACENTER",
			Name:   "vmwarevsphere-datacenter",
			Usage:  "vSphere datacenter for virtual machine",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_FOLDER",
			Name:   "vmwarevsphere-folder",
			Usage:  "vSphere folder for the docker VM. This folder must already exist in the datacenter",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_POOL",
			Name:   "vmwarevsphere-pool",
			Usage:  "vSphere resource pool for docker VM",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_HOSTSYSTEM",
			Name:   "vmwarevsphere-hostsystem",
			Usage:  "vSphere compute resource where the docker VM will be instantiated. This can be omitted if using a cluster with DRS",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "VSPHERE_CFGPARAM",
			Name:   "vmwarevsphere-cfgparam",
			Usage:  "vSphere vm configuration parameters (used for guestinfo)",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_CLOUDINIT",
			Name:   "vmwarevsphere-cloudinit",
			Usage:  "vSphere cloud-init filepath or url to add to guestinfo, filepath will be read and base64 encoded before adding",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_CLOUD_CONFIG",
			Name:   "vmwarevsphere-cloud-config",
			Usage:  "Filepath to a cloud-config yaml file to put into the ISO user-data",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_VAPP_IPPROTOCOL",
			Name:   "vmwarevsphere-vapp-ipprotocol",
			Usage:  "vSphere vApp IP protocol for this deployment. Supported values are: IPv4 and IPv6",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_VAPP_IPALLOCATIONPOLICY",
			Name:   "vmwarevsphere-vapp-ipallocationpolicy",
			Usage:  "vSphere vApp IP allocation policy. Supported values are: dhcp, fixed, transient and fixedAllocated",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_VAPP_TRANSPORT",
			Name:   "vmwarevsphere-vapp-transport",
			Usage:  "vSphere OVF environment transports to use for properties. Supported values are: iso and com.vmware.guestInfo",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "VSPHERE_VAPP_PROPERTY",
			Name:   "vmwarevsphere-vapp-property",
			Usage:  "vSphere vApp properties",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_CREATION_TYPE",
			Name:   "vmwarevsphere-creation-type",
			Usage:  "Creation type when creating a new virtual machine. Supported values: vm, template, library, legacy",
			Value:  creationTypeLegacy,
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_CLONE_FROM",
			Name:   "vmwarevsphere-clone-from",
			Usage:  "If you choose creation type clone a name of what you want to clone is required",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_CONTENT_LIBRARY",
			Name:   "vmwarevsphere-content-library",
			Usage:  "If you choose to clone from a content library template specify the name of the library",
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_SSH_USER",
			Name:   "vmwarevsphere-ssh-user",
			Usage:  "If using a non-B2D image you can specify the ssh user",
			Value:  defaultSSHUser,
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_SSH_PASSWORD",
			Name:   "vmwarevsphere-ssh-password",
			Usage:  "If using a non-B2D image you can specify the ssh password",
			Value:  defaultSSHPass,
		},
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_SSH_PORT",
			Name:   "vmwarevsphere-ssh-port",
			Usage:  "If using a non-B2D image you can specify the ssh port",
			Value:  drivers.DefaultSSHPort,
		},
		mcnflag.StringFlag{
			EnvVar: "VSPHERE_SSH_USER_GROUP",
			Name:   "vmwarevsphere-ssh-user-group",
			Usage:  "If using a non-B2D image the uploaded keys will need chown'ed, defaults to staff e.g. docker:staff",
			Value:  defaultSSHUserGroup,
		},
		mcnflag.StringFlag{
			EnvVar: "",
			Name:   "vmwarevsphere-os",
			Usage:  "If using a non-B2D image you can specify the desired machine OS",
			Value:  defaultMachineOS,
		},
		mcnflag.StringSliceFlag{
			EnvVar: "",
			Name:   "vmwarevsphere-tag",
			Usage:  "vSphere tag id e.g. urn:xxx",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "",
			Name:   "vmwarevsphere-custom-attribute",
			Usage:  "vSphere custom attribute, format key/value e.g. '200=my custom value'",
		},
		mcnflag.IntFlag{
			EnvVar: "VSPHERE_GRACEFUL_SHUTDOWN_TIMEOUT",
			Name:   "vmwarevsphere-graceful-shutdown-timeout",
			Usage:  "How many seconds to wait before timing out when attempting a graceful shutdown for a vSphere virtual machine. A force destroy will perform when the value is zero.",
		},
	}
}

// UnmarshalJSON loads driver config from JSON. This function is used by the RPCServerDriver that wraps
// all drivers as a means of populating an already-initialized driver with new configuration.
// See `RPCServerDriver.SetConfigRaw`.
func (d *Driver) UnmarshalJSON(data []byte) error {
	// Unmarshal driver config into an aliased type to prevent infinite recursion on UnmarshalJSON.
	type targetDriver Driver

	// Copy data from `d` to `target` before unmarshalling. This will ensure that already-initialized values
	// from `d` that are left untouched during unmarshal (like functions) are preserved.
	target := targetDriver(*d)

	if err := json.Unmarshal(data, &target); err != nil {
		return fmt.Errorf("error unmarshalling driver config from JSON: %w", err)
	}

	// Copy unmarshalled data back to `d`.
	*d = Driver(target)

	// Make sure to reload values that are subject to change from envvars and os.Args.
	driverOpts := rpcdriver.GetDriverOpts(d.GetCreateFlags(), os.Args)
	if _, ok := driverOpts.Values["vmwarevsphere-ssh-user"]; ok {
		d.SSHUser = driverOpts.String("vmwarevsphere-ssh-user")
	}

	if _, ok := driverOpts.Values["vmwarevsphere-ssh-password"]; ok {
		d.SSHPassword = driverOpts.String("vmwarevsphere-ssh-password")
	}

	if _, ok := driverOpts.Values["vmwarevsphere-vcenter"]; ok {
		d.IP = driverOpts.String("vmwarevsphere-vcenter")
	}

	if _, ok := driverOpts.Values["vmwarevsphere-username"]; ok {
		d.Username = driverOpts.String("vmwarevsphere-username")
	}

	if _, ok := driverOpts.Values["vmwarevsphere-password"]; ok {
		d.Password = driverOpts.String("vmwarevsphere-password")
	}

	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.SSHUser = flags.String("vmwarevsphere-ssh-user")
	d.SSHPassword = flags.String("vmwarevsphere-ssh-password")
	d.SSHPort = flags.Int("vmwarevsphere-ssh-port")
	d.SSHUserGroup = flags.String("vmwarevsphere-ssh-user-group")
	d.CPU = flags.Int("vmwarevsphere-cpu-count")
	d.Memory = flags.Int("vmwarevsphere-memory-size")
	d.DiskSize = flags.Int("vmwarevsphere-disk-size")
	d.Boot2DockerURL = flags.String("vmwarevsphere-boot2docker-url")
	d.IP = flags.String("vmwarevsphere-vcenter")
	d.Port = flags.Int("vmwarevsphere-vcenter-port")
	d.Username = flags.String("vmwarevsphere-username")
	d.Password = flags.String("vmwarevsphere-password")
	d.Networks = flags.StringSlice("vmwarevsphere-network")
	d.Tags = flags.StringSlice("vmwarevsphere-tag")
	d.CustomAttributes = flags.StringSlice("vmwarevsphere-custom-attribute")
	d.Datastore = flags.String("vmwarevsphere-datastore")
	d.DatastoreCluster = flags.String("vmwarevsphere-datastore-cluster")
	d.Datacenter = flags.String("vmwarevsphere-datacenter")
	// Sanitize input on ingress.
	d.Folder = flags.String("vmwarevsphere-folder")
	d.Pool = flags.String("vmwarevsphere-pool")
	d.HostSystem = flags.String("vmwarevsphere-hostsystem")
	d.CfgParams = flags.StringSlice("vmwarevsphere-cfgparam")
	d.CloudInit = flags.String("vmwarevsphere-cloudinit")
	d.CloudConfig = flags.String("vmwarevsphere-cloud-config")
	if d.CloudConfig != "" {
		if _, err := os.Stat(d.CloudConfig); err != nil {
			return err
		}
		ud, err := os.ReadFile(d.CloudConfig)
		if err != nil {
			return err
		}
		d.CloudConfig = string(ud)
	}

	d.VAppIpProtocol = flags.String("vmwarevsphere-vapp-ipprotocol")
	d.VAppIpAllocationPolicy = flags.String("vmwarevsphere-vapp-ipallocationpolicy")
	d.VAppTransport = flags.String("vmwarevsphere-vapp-transport")
	d.VAppProperties = flags.StringSlice("vmwarevsphere-vapp-property")
	d.SetSwarmConfigFromFlags(flags)
	d.ISO = d.ResolveStorePath(isoFilename)

	d.CreationType = flags.String("vmwarevsphere-creation-type")
	if _, ok := supportedCreationTypes[d.CreationType]; !ok {
		return fmt.Errorf("creation type %s not supported", d.CreationType)
	}
	err := d.SetMachineOSFromFlags(flags)
	if err != nil {
		return err
	}

	d.ContentLibrary = flags.String("vmwarevsphere-content-library")
	if d.CreationType != "legacy" {
		d.CloneFrom = flags.String("vmwarevsphere-clone-from")
		if d.CloneFrom == "" {
			return fmt.Errorf("creation type clone needs a VM name to clone from, use --vmwarevsphere-clone-from")
		}
	}

	d.GracefulShutdownTimeout = flags.Int("vmwarevsphere-graceful-shutdown-timeout")
	if d.GracefulShutdownTimeout < 0 {
		return errors.New("vmwarevsphere-graceful-shutdown-timeout can not be negative")
	}

	return nil
}

type AuthFlag struct {
	auth types.NamePasswordAuthentication
}

func NewAuthFlag(u, p string) *AuthFlag {
	return &AuthFlag{
		auth: types.NamePasswordAuthentication{
			Username: u,
			Password: p,
		},
	}
}

func (f *AuthFlag) Auth() types.BaseGuestAuthentication {
	return &f.auth
}

type FileAttrFlag struct {
	types.GuestPosixFileAttributes
}

func (f *FileAttrFlag) SetPerms(owner, group, perms int) {
	owner32 := int32(owner)
	group32 := int32(group)
	f.OwnerId = &owner32
	f.GroupId = &group32
	f.Permissions = int64(perms)
}

func (f *FileAttrFlag) Attr() types.BaseGuestFileAttributes {
	return &f.GuestPosixFileAttributes
}

func (d *Driver) SetMachineOSFromFlags(flags drivers.DriverOptions) error {
	d.OS = strings.ToLower(flags.String("vmwarevsphere-os"))
	if d.OS == "" {
		d.OS = defaultMachineOS
		return nil
	}
	err := d.CheckMachineOS(d.OS)
	if !err {
		return fmt.Errorf("[SetMachineOSFromFlags] Machine [%s] has an unsupported MachineOS [%s]\n", d.MachineName, d.OS)
	}
	return nil
}

func (d *Driver) CheckMachineOS(os string) bool {
	_, ok := supportedMachineOS[os]
	return ok
}
