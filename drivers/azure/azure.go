package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2019-06-01/storage"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/rancher/machine/drivers/azure/azureutil"
	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/state"
)

const (
	defaultAzureEnvironment     = "AzurePublicCloud"
	defaultAzureResourceGroup   = "docker-machine"
	defaultAzureSize            = "Standard_D2_v2"
	defaultAzureLocation        = "westus"
	defaultSSHUser              = "docker-user" // 'root' not allowed on Azure
	defaultDockerPort           = 2376
	defaultAzureImage           = "canonical:ubuntu-24_04-lts:server-gen1:latest"
	defaultAzureVNet            = "docker-machine-vnet"
	defaultAzureSubnet          = "docker-machine"
	defaultAzureSubnetPrefix    = "192.168.0.0/16"
	defaultStorageType          = string(storage.StandardLRS)
	defaultAzureAvailabilitySet = "docker-machine"
)

const (
	flAzureEnvironment               = "azure-environment"
	flAzureSubscriptionID            = "azure-subscription-id"
	flAzureTenantID                  = "azure-tenant-id"
	flAzureResourceGroup             = "azure-resource-group"
	flAzureSSHUser                   = "azure-ssh-user"
	flAzureDockerPort                = "azure-docker-port"
	flAzureLocation                  = "azure-location"
	flAzureSize                      = "azure-size"
	flAzureImage                     = "azure-image"
	flAzureVNet                      = "azure-vnet"
	flAzureSubnet                    = "azure-subnet"
	flAzureSubnetPrefix              = "azure-subnet-prefix"
	flAzureAvailabilitySet           = "azure-availability-set"
	flAzureManagedDisks              = "azure-managed-disks"
	flAzureFaultDomainCount          = "azure-fault-domain-count"
	flAzureUpdateDomainCount         = "azure-update-domain-count"
	flAzureDiskSize                  = "azure-disk-size"
	flAzurePorts                     = "azure-open-port"
	flAzurePrivateIPAddr             = "azure-private-ip-address"
	flAzureUsePrivateIP              = "azure-use-private-ip"
	flAzureStaticPublicIP            = "azure-static-public-ip"
	flAzureNoPublicIP                = "azure-no-public-ip"
	flAzureDNSLabel                  = "azure-dns"
	flAzureStorageType               = "azure-storage-type"
	flAzureCustomData                = "azure-custom-data"
	flAzureClientID                  = "azure-client-id"
	flAzureClientSecret              = "azure-client-secret"
	flAzureNSG                       = "azure-nsg"
	flAzurePlan                      = "azure-plan"
	flAzureTags                      = "azure-tags"
	flAzureAcceleratedNetworking     = "azure-accelerated-networking"
	flAzureEnablePublicIPStandardSKU = "azure-enable-public-ip-standard-sku"
	flAzureAvailabilityZones         = "azure-availability-zone"
)

const (
	driverName = "azure"
	sshPort    = 22
)

// Driver represents Azure Docker Machine Driver.
type Driver struct {
	*drivers.BaseDriver

	ClientID     string // service principal account name
	ClientSecret string // service principal account password

	Environment    string
	SubscriptionID string
	TenantID       string
	ResourceGroup  string

	DockerPort                int
	Location                  string
	Size                      string
	Image                     string
	VirtualNetwork            string
	SubnetName                string
	SubnetPrefix              string
	AvailabilitySet           string
	NSG                       string
	Plan                      string
	ManagedDisks              bool
	FaultCount                int
	UpdateCount               int
	DiskSize                  int
	StorageType               string
	Tags                      map[string]*string
	AcceleratedNetworking     bool
	AvailabilityZone          string
	EnablePublicIPStandardSKU bool

	OpenPorts      []string
	PrivateIPAddr  string
	UsePrivateIP   bool
	NoPublicIP     bool
	DNSLabel       string
	StaticPublicIP bool
	CustomDataFile string // Can provide cloud-config file here

	// Ephemeral fields
	deploymentCtx *azureutil.DeploymentContext
	resolvedIP    string // cache
	nsgResource   azure.Resource
	nsgUsedInPool bool
}

// NewDriver returns a new driver instance.
func NewDriver(hostName, storePath string) drivers.Driver {
	// NOTE(ahmetalpbalkan): any driver initialization I do here gets lost
	// afterwards, especially for non-Create RPC calls. Therefore I am mostly
	// making rest of the driver stateless by just relying on the following
	// piece of info.
	d := &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return d
}

// GetCreateFlags returns list of create flags driver accepts.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   flAzureEnvironment,
			Usage:  "Azure environment (e.g. AzurePublicCloud, AzureChinaCloud)",
			EnvVar: "AZURE_ENVIRONMENT",
			Value:  defaultAzureEnvironment,
		},
		mcnflag.StringFlag{
			Name:   flAzureSubscriptionID,
			Usage:  "Azure Subscription ID",
			EnvVar: "AZURE_SUBSCRIPTION_ID",
		},
		mcnflag.StringFlag{
			Name:   flAzureTenantID,
			Usage:  "Azure Tenant ID",
			EnvVar: "AZURE_TENANT_ID",
		},
		mcnflag.StringFlag{
			Name:   flAzureResourceGroup,
			Usage:  "Azure Resource Group name (will be created if missing)",
			EnvVar: "AZURE_RESOURCE_GROUP",
			Value:  defaultAzureResourceGroup,
		},
		mcnflag.StringFlag{
			Name:   flAzureSSHUser,
			Usage:  "Username for SSH login",
			EnvVar: "AZURE_SSH_USER",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			Name:   flAzureDockerPort,
			Usage:  "Port number for Docker engine",
			EnvVar: "AZURE_DOCKER_PORT",
			Value:  defaultDockerPort,
		},
		mcnflag.StringFlag{
			Name:   flAzureLocation,
			Usage:  "Azure region to create the virtual machine",
			EnvVar: "AZURE_LOCATION",
			Value:  defaultAzureLocation,
		},
		mcnflag.StringFlag{
			Name:   flAzureSize,
			Usage:  "Size for Azure Virtual Machine",
			EnvVar: "AZURE_SIZE",
			Value:  defaultAzureSize,
		},
		mcnflag.StringFlag{
			Name:   flAzureImage,
			Usage:  "Azure virtual machine OS image",
			EnvVar: "AZURE_IMAGE",
			Value:  defaultAzureImage,
		},
		mcnflag.StringFlag{
			Name:   flAzureVNet,
			Usage:  "Azure Virtual Network name to connect the virtual machine (in [resourcegroup:]name format)",
			EnvVar: "AZURE_VNET",
			Value:  defaultAzureVNet,
		},
		mcnflag.StringFlag{
			Name:   flAzureSubnet,
			Usage:  "Azure Subnet Name to be used within the Virtual Network",
			EnvVar: "AZURE_SUBNET",
			Value:  defaultAzureSubnet,
		},
		mcnflag.StringFlag{
			Name:   flAzureSubnetPrefix,
			Usage:  "Private CIDR block to be used for the new subnet, should comply RFC 1918",
			EnvVar: "AZURE_SUBNET_PREFIX",
			Value:  defaultAzureSubnetPrefix,
		},
		mcnflag.StringFlag{
			Name:   flAzureAvailabilitySet,
			Usage:  "Azure Availability Set to place the virtual machine into",
			EnvVar: "AZURE_AVAILABILITY_SET",
			Value:  defaultAzureAvailabilitySet,
		},
		mcnflag.StringFlag{
			Name:   flAzureNSG,
			Usage:  "Azure Network Security Group to assign this node to (accepts either a name or resource ID, default is to create a new NSG for each machine)",
			EnvVar: "AZURE_NSG",
			Value:  "",
		},
		mcnflag.StringFlag{
			Name:  flAzurePlan,
			Usage: "Purchase plan for Azure Virtual Machine (in <publisher>:<product>:<plan> format)",
		},
		mcnflag.BoolFlag{
			Name:   flAzureManagedDisks,
			Usage:  "Configures VM and availability set for managed disks",
			EnvVar: "AZURE_MANAGED_DISKS",
		},
		mcnflag.IntFlag{
			Name:   flAzureFaultDomainCount,
			Usage:  "Fault domain count to use for availability set",
			EnvVar: "AZURE_FAULT_DOMAIN_COUNT",
			Value:  3,
		},
		mcnflag.IntFlag{
			Name:   flAzureUpdateDomainCount,
			Usage:  "Update domain count to use for availability set",
			EnvVar: "AZURE_UPDATE_DOMAIN_COUNT",
			Value:  5,
		},
		mcnflag.IntFlag{
			Name:   flAzureDiskSize,
			Usage:  "Disk size if using managed disk",
			EnvVar: "AZURE_DISK_SIZE",
			Value:  30,
		},
		mcnflag.StringFlag{
			Name:   flAzureCustomData,
			EnvVar: "AZURE_CUSTOM_DATA_FILE",
			Usage:  "Path to file with custom-data",
		},
		mcnflag.StringFlag{
			Name:  flAzurePrivateIPAddr,
			Usage: "Specify a static private IP address for the machine",
		},
		mcnflag.StringFlag{
			Name:   flAzureStorageType,
			Usage:  "Type of Storage Account to host the OS Disk for the machine",
			EnvVar: "AZURE_STORAGE_TYPE",
			Value:  defaultStorageType,
		},
		mcnflag.BoolFlag{
			Name:  flAzureUsePrivateIP,
			Usage: "Use private IP address of the machine to connect",
		},
		mcnflag.BoolFlag{
			Name:  flAzureNoPublicIP,
			Usage: "Do not create a public IP address for the machine",
		},
		mcnflag.BoolFlag{
			Name:  flAzureStaticPublicIP,
			Usage: "Assign a static public IP address to the machine",
		},
		mcnflag.StringFlag{
			Name:   flAzureDNSLabel,
			Usage:  "A unique DNS label for the public IP adddress",
			EnvVar: "AZURE_DNS_LABEL",
		},
		mcnflag.StringSliceFlag{
			Name:  flAzurePorts,
			Usage: "Make the specified port number accessible from the Internet",
		},
		mcnflag.StringFlag{
			Name:   flAzureClientID,
			Usage:  "Azure Service Principal Account ID (optional, browser auth is used if not specified)",
			EnvVar: "AZURE_CLIENT_ID",
		},
		mcnflag.StringFlag{
			Name:   flAzureClientSecret,
			Usage:  "Azure Service Principal Account password (optional, browser auth is used if not specified)",
			EnvVar: "AZURE_CLIENT_SECRET",
		},
		mcnflag.StringFlag{
			Name:   flAzureTags,
			Usage:  "Tags to be applied to the Azure VM instance",
			EnvVar: "AZURE_TAGS",
		},
		mcnflag.StringFlag{
			Name:   flAzureAvailabilityZones,
			Usage:  "Specify the Availability Zones the Azure resources should be created in",
			EnvVar: "AZURE_AVAILABILITY_ZONE",
		},
		mcnflag.BoolFlag{
			Name:   flAzureEnablePublicIPStandardSKU,
			Usage:  "Specify if a Standard SKU should be used for the Public IP of the Azure VM",
			EnvVar: "AZURE_STANDARD_PUBLIC_IP_SKU",
		},
		mcnflag.BoolFlag{
			Name:   flAzureAcceleratedNetworking,
			Usage:  "Specify if an Accelerated Networking NIC should be created for your VM",
			EnvVar: "AZURE_ACCELERATED_NETWORKING",
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
	if _, ok := driverOpts.Values[flAzureEnvironment]; ok {
		d.Environment = driverOpts.String(flAzureEnvironment)
	}

	if _, ok := driverOpts.Values[flAzureSubscriptionID]; ok {
		d.SubscriptionID = driverOpts.String(flAzureSubscriptionID)
	}

	if _, ok := driverOpts.Values[flAzureClientID]; ok {
		d.ClientID = driverOpts.String(flAzureClientID)
	}

	if _, ok := driverOpts.Values[flAzureClientSecret]; ok {
		d.ClientSecret = driverOpts.String(flAzureClientSecret)
	}

	return nil
}

// SetConfigFromFlags initializes driver values from the command line values
// and checks if the arguments have values.
func (d *Driver) SetConfigFromFlags(fl drivers.DriverOptions) error {
	// Initialize driver context for machine
	d.deploymentCtx = &azureutil.DeploymentContext{}

	// Required string flags
	flags := []struct {
		target *string
		flag   string
	}{
		{&d.BaseDriver.SSHUser, flAzureSSHUser},
		{&d.SubscriptionID, flAzureSubscriptionID},
		{&d.ResourceGroup, flAzureResourceGroup},
		{&d.Location, flAzureLocation},
		{&d.Size, flAzureSize},
		{&d.Image, flAzureImage},
		{&d.VirtualNetwork, flAzureVNet},
		{&d.SubnetName, flAzureSubnet},
		{&d.SubnetPrefix, flAzureSubnetPrefix},
		{&d.AvailabilitySet, flAzureAvailabilitySet},
		{&d.StorageType, flAzureStorageType},
	}
	for _, f := range flags {
		*f.target = fl.String(f.flag)
		if *f.target == "" {
			return requiredOptionError(f.flag)
		}
	}

	// Optional flags or Flags of other types
	d.AvailabilityZone = fl.String(flAzureAvailabilityZones)
	d.EnablePublicIPStandardSKU = fl.Bool(flAzureEnablePublicIPStandardSKU)
	d.Tags = azureutil.BuildInstanceTags(fl.String(flAzureTags))
	d.AcceleratedNetworking = fl.Bool(flAzureAcceleratedNetworking)
	d.Environment = fl.String(flAzureEnvironment)
	d.OpenPorts = fl.StringSlice(flAzurePorts)
	d.PrivateIPAddr = fl.String(flAzurePrivateIPAddr)
	d.UsePrivateIP = fl.Bool(flAzureUsePrivateIP)
	d.NoPublicIP = fl.Bool(flAzureNoPublicIP)
	d.StaticPublicIP = fl.Bool(flAzureStaticPublicIP)
	d.DockerPort = fl.Int(flAzureDockerPort)
	d.DNSLabel = fl.String(flAzureDNSLabel)
	d.CustomDataFile = fl.String(flAzureCustomData)
	d.ManagedDisks = fl.Bool(flAzureManagedDisks)
	d.FaultCount = fl.Int(flAzureFaultDomainCount)
	d.UpdateCount = fl.Int(flAzureUpdateDomainCount)
	d.DiskSize = fl.Int(flAzureDiskSize)
	d.NSG = fl.String(flAzureNSG)
	d.Plan = fl.String(flAzurePlan)

	d.ClientID = fl.String(flAzureClientID)
	d.ClientSecret = fl.String(flAzureClientSecret)
	d.TenantID = fl.String(flAzureTenantID)

	// Set flags on the BaseDriver
	d.BaseDriver.SSHPort = sshPort
	d.SetSwarmConfigFromFlags(fl)

	log.Debug("Set configuration from flags.")
	return nil
}

// DriverName returns the name of the driver.
func (d *Driver) DriverName() string { return driverName }

// PreCreateCheck validates if driver values are valid to create the machine.
func (d *Driver) PreCreateCheck() (err error) {
	if d.CustomDataFile != "" {
		if _, err := os.Stat(d.CustomDataFile); os.IsNotExist(err) {
			return fmt.Errorf("custom-data file %s could not be found", d.CustomDataFile)
		}
	}

	if d.AvailabilityZone != "" {
		if !d.ManagedDisks {
			return fmt.Errorf("Managed Disks must be used when creating resources in specific Availability Zones (--azure-managed-disks)")
		}
		if v, err := strconv.Atoi(d.AvailabilityZone); err != nil || v == 0 {
			return fmt.Errorf("Each VM can only be assigned to a single Availability Zone. Each zone is denoted by an integer greater than 0")
		}
		if !d.EnablePublicIPStandardSKU {
			return fmt.Errorf("The Standard Public IP SKU must be enabled when creating resources in specific Availablity Zones (--azure-enable-public-ip-standard-sku)")
		}
		if d.AvailabilitySet != "" {
			log.Warn("Both an Availability Set and Availability Zone were specified. Skipping creation of the Availability Set, only creating resources in the specified Availability Zone.")
		}
	}

	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}

	// Register used resource providers with current Azure subscription.
	if err := c.RegisterResourceProviders(ctx,
		"Microsoft.Compute",
		"Microsoft.Network",
		"Microsoft.Storage",
		"Microsoft.Resources"); err != nil {
		return err
	}

	// Validate if firewall rules can be read correctly
	d.deploymentCtx.FirewallRules, err = d.getSecurityRules(d.OpenPorts)
	if err != nil {
		return err
	}

	// Check if virtual machine exists. An existing virtual machine cannot be updated.
	log.Debug("Checking if Virtual Machine already exists.")
	exists, err := c.VirtualMachineExists(ctx, d.ResourceGroup, d.naming().VM())
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("Virtual Machine with name %s already exists in resource group %q", d.naming().VM(), d.ResourceGroup)
	}

	// NOTE(ahmetalpbalkan) we could have done more checks here but Azure often
	// returns meaningful error messages and it would be repeating the backend
	// logic on the client side. Some examples:
	//   - Deployment of a machine to an existing Virtual Network fails if
	//     virtual network is in a different region.
	//   - Changing IP Address space of a subnet would fail if there are machines
	//     running in the Virtual Network.
	log.Info("Completed machine pre-create checks.")
	return nil
}

// Create creates the virtual machine.
func (d *Driver) Create() error {
	// NOTE(ahmetalpbalkan): We can probably parallelize the sh*t out of this.
	// However that would lead to a concurrency logic and while creation of a
	// resource fails, other ones would be kicked off, which could lead to a
	// resource leak. This is slower but safer.
	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}

	var customData string
	if d.CustomDataFile != "" {
		buf, err := os.ReadFile(d.CustomDataFile)
		if err != nil {
			return err
		}
		customData = base64.StdEncoding.EncodeToString(buf)
	}
	d.nsgUsedInPool = len(d.NSG) > 0
	if d.nsgResource, err = d.resolveNSGReference(d.NSG); err != nil {
		return err
	}

	if err := c.CreateResourceGroup(ctx, d.ResourceGroup, d.Location); err != nil {
		return err
	}
	// availability sets and availability zones cannot be used together. The presence of an Availability Zone indicates that an Availability set should not be created / used
	if d.AvailabilityZone == "" {
		if err := c.CreateAvailabilitySetIfNotExists(ctx, d.deploymentCtx, d.ResourceGroup, d.AvailabilitySet, d.Location, d.ManagedDisks, int32(d.FaultCount), int32(d.UpdateCount)); err != nil {
			return err
		}
	}
	if err := c.CreateNetworkSecurityGroup(ctx, d.deploymentCtx, d.ResourceGroup, d.nsgResource, d.Location, d.nsgUsedInPool, d.deploymentCtx.FirewallRules); err != nil {
		return err
	}
	vnetResourceGroup, vNetName := parseVirtualNetwork(d.VirtualNetwork, d.ResourceGroup)
	if err := c.CreateVirtualNetworkIfNotExists(ctx, vnetResourceGroup, vNetName, d.Location); err != nil {
		return err
	}
	if err := c.CreateSubnet(ctx, d.deploymentCtx, vnetResourceGroup, vNetName, d.SubnetName, d.SubnetPrefix); err != nil {
		return err
	}
	if d.NoPublicIP {
		log.Info("Not creating a public IP address.")
	} else {
		if err := c.CreatePublicIPAddress(ctx, d.deploymentCtx, d.ResourceGroup, d.naming().IP(), d.Location, d.StaticPublicIP, d.DNSLabel, d.EnablePublicIPStandardSKU); err != nil {
			return err
		}
	}
	if err := c.CreateNetworkInterface(ctx, d.deploymentCtx, d.ResourceGroup, d.naming().NIC(), d.Location,
		d.deploymentCtx.PublicIPAddressID, d.deploymentCtx.SubnetID, d.deploymentCtx.NetworkSecurityGroupID, d.PrivateIPAddr, d.AcceleratedNetworking); err != nil {
		return err
	}
	if !d.ManagedDisks {
		// storage account is only necessary when using unmanaged disks
		if err := c.CreateStorageAccount(ctx, d.deploymentCtx, d.ResourceGroup, d.Location, storage.SkuName(d.StorageType)); err != nil {
			return err
		}
	}
	if err := d.generateSSHKey(d.deploymentCtx); err != nil {
		return err
	}
	if err := c.CreateVirtualMachine(ctx, d.ResourceGroup, d.naming().VM(), d.Location, d.Size, d.deploymentCtx.AvailabilitySetID,
		d.deploymentCtx.NetworkInterfaceID, d.BaseDriver.SSHUser, d.deploymentCtx.SSHPublicKey, d.Image, d.Plan, customData, d.deploymentCtx.StorageAccount,
		d.ManagedDisks, d.StorageType, int32(d.DiskSize), d.Tags, d.AvailabilityZone); err != nil {
		return err
	}
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	return nil
}

// Remove deletes the virtual machine and resources associated to it.
func (d *Driver) Remove() error {
	if err := d.checkLegacyDriver(false); err != nil {
		return err
	}

	// NOTE(ahmetalpbalkan):
	//   - remove attempts are best effort and if a resource is already gone, we
	//     continue removing other resources instead of failing.
	//   - we can probably do a lot of parallelization here but a sequential
	//     logic works fine too. If we were to detach the NIC from the VM and
	//     then delete the VM, this could enable some parallelization.

	log.Info("NOTICE: Please check Azure portal/CLI to make sure you have no leftover resources to avoid unexpected charges.")
	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}
	d.nsgUsedInPool = len(d.NSG) > 0
	if d.nsgResource, err = d.resolveNSGReference(d.NSG); err != nil {
		return err
	}

	if err := c.DeleteVirtualMachineIfExists(ctx, d.ResourceGroup, d.naming().VM()); err != nil {
		return err
	}
	if err := c.DeleteNetworkInterfaceIfExists(ctx, d.ResourceGroup, d.naming().NIC()); err != nil {
		return err
	}
	if err := c.DeletePublicIPAddressIfExists(ctx, d.ResourceGroup, d.naming().IP()); err != nil {
		return err
	}
	if err := c.DeleteNetworkSecurityGroupIfExists(ctx, d.nsgResource, d.nsgUsedInPool); err != nil {
		return err
	}
	// availability sets and availability zones cannot be used together. The absence of any Availability Zones indicates that an Availability set was created and should be deleted.
	if d.AvailabilityZone == "" {
		if err := c.CleanupAvailabilitySetIfExists(ctx, d.ResourceGroup, d.AvailabilitySet); err != nil {
			return err
		}
	}
	if err := c.CleanupSubnetIfExists(ctx, d.ResourceGroup, d.VirtualNetwork, d.SubnetName); err != nil {
		return err
	}
	err = c.CleanupVirtualNetworkIfExists(ctx, d.ResourceGroup, d.VirtualNetwork)
	return err
}

// GetIP returns public IP address or hostname of the machine instance.
func (d *Driver) GetIP() (string, error) {
	if err := d.checkLegacyDriver(true); err != nil {
		return "", err
	}

	if d.resolvedIP == "" {
		ctx := context.Background()
		ip, err := d.ipAddress(ctx)
		if err != nil {
			return "", err
		}
		d.resolvedIP = ip
	}
	log.Debugf("Machine IP address resolved to: %s", d.resolvedIP)
	return d.resolvedIP, nil
}

// GetSSHHostname returns an IP address or hostname for the machine instance.
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetURL returns a socket address to connect to Docker engine of the machine
// instance.
func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	// NOTE (ahmetalpbalkan) I noticed that this is not used until machine is
	// actually created and provisioned. By then GetIP() should be returning
	// a non-empty IP address as the VM is already allocated and connected to.
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	u := (&url.URL{
		Scheme: "tcp",
		Host:   net.JoinHostPort(ip, fmt.Sprintf("%d", d.DockerPort)),
	}).String()
	log.Debugf("Machine URL is resolved to: %s", u)
	return u, nil
}

// GetState returns the state of the virtual machine role instance.
func (d *Driver) GetState() (state.State, error) {
	if err := d.checkLegacyDriver(true); err != nil {
		return state.None, err
	}

	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return state.None, err
	}
	powerState, err := c.GetVirtualMachinePowerState(ctx,
		d.ResourceGroup, d.naming().VM())
	if err != nil {
		return state.None, err
	}

	machineState := machineStateForVMPowerState(powerState)
	log.Debugf("Determined Azure PowerState=%q, docker-machine state=%q",
		powerState, machineState)
	return machineState, nil
}

// Start issues a power on for the virtual machine instance.
func (d *Driver) Start() error {
	if err := d.checkLegacyDriver(true); err != nil {
		return err
	}

	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}
	return c.StartVirtualMachine(ctx, d.ResourceGroup, d.naming().VM())
}

// Stop issues a power off for the virtual machine instance.
func (d *Driver) Stop() error {
	if err := d.checkLegacyDriver(true); err != nil {
		return err
	}

	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}
	log.Info("NOTICE: Stopping an Azure Virtual Machine is just going to power it off, not deallocate.")
	log.Info("NOTICE: You should remove the machine if you would like to avoid unexpected costs.")
	return c.StopVirtualMachine(ctx, d.ResourceGroup, d.naming().VM(), false)
}

// Restart reboots the virtual machine instance.
func (d *Driver) Restart() error {
	if err := d.checkLegacyDriver(true); err != nil {
		return err
	}

	// NOTE(ahmetalpbalkan) Azure will always keep the VM in Running state
	// during the restart operation. Hence we rely on returned async operation
	// polling to make sure the reboot is waited upon.
	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}
	return c.RestartVirtualMachine(ctx, d.ResourceGroup, d.naming().VM())
}

// Kill stops the virtual machine role instance.
func (d *Driver) Kill() error {
	if err := d.checkLegacyDriver(true); err != nil {
		return err
	}

	ctx := context.Background()
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return err
	}
	return c.StopVirtualMachine(ctx, d.ResourceGroup, d.naming().VM(), true)
}

// checkLegacyDriver errors out if it encounters an Azure VM created with the
// legacy (<=0.6.0) docker-machine Azure driver.
func (d *Driver) checkLegacyDriver(short bool) error {
	if d.ResourceGroup == "" {
		if short {
			return errors.New("new azure driver cannot manage old VMs, downgrade to v0.6.0")
		}
		return errors.New("new azure driver uses the new Azure Resource Manager APIs and therefore cannot manage this existing machine created with old azure driver. Please downgrade to docker-machine 0.6.0 to continue using these machines or to remove them")
	}
	return nil
}
