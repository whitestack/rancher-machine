package openstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/utils/openstack/clientconfig"
)

type Driver struct {
	*drivers.BaseDriver
	AuthUrl                     string
	ActiveTimeout               int
	AllowedAddressPairs         []AllowedAddressPair
	Insecure                    bool
	CaCert                      string
	DomainId                    string
	DomainName                  string
	UserId                      string
	Username                    string
	Password                    string
	TenantName                  string
	TenantId                    string
	TenantDomainName            string
	TenantDomainId              string
	UserDomainName              string
	UserDomainId                string
	ApplicationCredentialId     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string
	Region                      string
	AvailabilityZone            string
	EndpointType                string
	MachineId                   string
	FlavorName                  string
	FlavorId                    string
	ImageName                   string
	ImageId                     string
	KeyPairName                 string
	NetworkNames                []string
	NetworkIds                  []string
	UserData                    []byte
	PrivateKeyFile              string
	SecurityGroups              []string
	FloatingIpPool              string
	ComputeNetwork              bool
	FloatingIpPoolId            string
	IpVersion                   int
	ConfigDrive                 bool
	BootFromVolume              bool
	VolumeName                  string
	VolumeDevicePath            string
	VolumeId                    string
	VolumeType                  string
	VolumeSize                  int
	client                      Client
	// ExistingKey keeps track of whether the key was created by us or we used an existing one. If an existing one was used, we shouldn't delete it when the machine is deleted.
	ExistingKey bool
}

type AllowedAddressPair struct {
	IPAddress   string
	NetworkName string
}

const (
	defaultSSHUser       = "root"
	defaultSSHPort       = 22
	defaultActiveTimeout = 200
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "OS_AUTH_URL",
			Name:   "openstack-auth-url",
			Usage:  "OpenStack authentication URL",
			Value:  "",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "OS_ALLOWED_ADDRESS_PAIRS",
			Name:   "openstack-allowed-address-pairs",
			Usage:  "Allowed address pairs for the instance (format: IP/CIDR:NetworkName or IP/CIDR)",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_INSECURE",
			Name:   "openstack-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_CACERT",
			Name:   "openstack-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_ID",
			Name:   "openstack-domain-id",
			Usage:  "OpenStack domain ID",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_DOMAIN_NAME",
			Name:   "openstack-domain-name",
			Usage:  "OpenStack domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_ID",
			Name:   "openstack-user-id",
			Usage:  "OpenStack user-id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USERNAME",
			Name:   "openstack-username",
			Usage:  "OpenStack username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PASSWORD",
			Name:   "openstack-password",
			Usage:  "OpenStack password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_NAME",
			Name:   "openstack-tenant-name",
			Usage:  "OpenStack tenant name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_ID",
			Name:   "openstack-tenant-id",
			Usage:  "OpenStack tenant id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_DOMAIN_NAME",
			Name:   "openstack-tenant-domain-name",
			Usage:  "OpenStack tenant domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_TENANT_DOMAIN_ID",
			Name:   "openstack-tenant-domain-id",
			Usage:  "OpenStack tenant domain id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_DOMAIN_NAME",
			Name:   "openstack-user-domain-name",
			Usage:  "OpenStack user domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_DOMAIN_ID",
			Name:   "openstack-user-domain-id",
			Usage:  "OpenStack user domain id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_APPLICATION_CREDENTIAL_ID",
			Name:   "openstack-application-credential-id",
			Usage:  "OpenStack application credential id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_APPLICATION_CREDENTIAL_NAME",
			Name:   "openstack-application-credential-name",
			Usage:  "OpenStack application credential name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_APPLICATION_CREDENTIAL_SECRET",
			Name:   "openstack-application-credential-secret",
			Usage:  "OpenStack application credential secret",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_REGION_NAME",
			Name:   "openstack-region",
			Usage:  "OpenStack region name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_AVAILABILITY_ZONE",
			Name:   "openstack-availability-zone",
			Usage:  "OpenStack availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_ENDPOINT_TYPE",
			Name:   "openstack-endpoint-type",
			Usage:  "OpenStack endpoint type (adminURL, internalURL or publicURL)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_ID",
			Name:   "openstack-flavor-id",
			Usage:  "OpenStack flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLAVOR_NAME",
			Name:   "openstack-flavor-name",
			Usage:  "OpenStack flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_ID",
			Name:   "openstack-image-id",
			Usage:  "OpenStack image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_IMAGE_NAME",
			Name:   "openstack-image-name",
			Usage:  "OpenStack image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_KEYPAIR_NAME",
			Name:   "openstack-keypair-name",
			Usage:  "OpenStack keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_NETWORK_ID",
			Name:   "openstack-net-id",
			Usage:  "OpenStack comma seperated network id(s) the machine will be connected on. (If floating ip pool is given, driver tries to find connected port in order of given networks to update floating ip)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_PRIVATE_KEY_FILE",
			Name:   "openstack-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_USER_DATA_FILE",
			Name:   "openstack-user-data-file",
			Usage:  "File containing an openstack userdata script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_NETWORK_NAME",
			Name:   "openstack-net-name",
			Usage:  "OpenStack comma seperated network name(s) the machine will be connected on. (If floating ip pool is given, driver tries to find connected port in order of given networks to update floating ip)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SECURITY_GROUPS",
			Name:   "openstack-sec-groups",
			Usage:  "OpenStack comma separated security groups for the machine",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_NOVA_NETWORK",
			Name:   "openstack-nova-network",
			Usage:  "Use the nova networking services instead of neutron.",
		},
		mcnflag.StringFlag{
			EnvVar: "OS_FLOATINGIP_POOL",
			Name:   "openstack-floatingip-pool",
			Usage:  "OpenStack floating IP pool to get an IP from to assign to the instance",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "OS_IP_VERSION",
			Name:   "openstack-ip-version",
			Usage:  "OpenStack version of IP address assigned for the machine",
			Value:  4,
		},
		mcnflag.StringFlag{
			EnvVar: "OS_SSH_USER",
			Name:   "openstack-ssh-user",
			Usage:  "OpenStack SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_SSH_PORT",
			Name:   "openstack-ssh-port",
			Usage:  "OpenStack SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "OS_ACTIVE_TIMEOUT",
			Name:   "openstack-active-timeout",
			Usage:  "OpenStack active timeout",
			Value:  defaultActiveTimeout,
		},
		mcnflag.BoolFlag{
			EnvVar: "OS_CONFIG_DRIVE",
			Name:   "openstack-config-drive",
			Usage:  "Enables the OpenStack config drive for the instance",
		},
		mcnflag.BoolFlag{
			Name:  "openstack-boot-from-volume",
			Usage: "Enables Openstack instance to boot from volume as ROOT",
		},
		mcnflag.StringFlag{
			Name:  "openstack-volume-name",
			Usage: "OpenStack volume name (creating); Default: 'rancher-machine-name'",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openstack-volume-device-path",
			Usage: "OpenStack volume device path (attaching); Omit for auto '/dev/vdb'",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openstack-volume-id",
			Usage: "OpenStack volume id (existing)",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openstack-volume-type",
			Usage: "OpenStack volume type (ssd, ...)",
			Value: "",
		},
		mcnflag.IntFlag{
			Name:  "openstack-volume-size",
			Usage: "OpenStack volume size (GiB) when creating a volume",
			Value: 0,
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)
}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) SetClient(client Client) {
	d.client = client
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "openstack"
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
	if _, ok := driverOpts.Values["openstack-auth-url"]; ok {
		d.AuthUrl = driverOpts.String("openstack-auth-url")
	}

	if _, ok := driverOpts.Values["openstack-user-id"]; ok {
		d.UserId = driverOpts.String("openstack-user-id")
	}

	if _, ok := driverOpts.Values["openstack-username"]; ok {
		d.Username = driverOpts.String("openstack-username")
	}

	if _, ok := driverOpts.Values["openstack-password"]; ok {
		d.Password = driverOpts.String("openstack-password")
	}

	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("openstack-auth-url")
	d.ActiveTimeout = flags.Int("openstack-active-timeout")
	d.Insecure = flags.Bool("openstack-insecure")
	d.CaCert = flags.String("openstack-cacert")
	d.DomainId = flags.String("openstack-domain-id")
	d.DomainName = flags.String("openstack-domain-name")
	d.UserId = flags.String("openstack-user-id")
	d.Username = flags.String("openstack-username")
	d.Password = flags.String("openstack-password")
	d.TenantName = flags.String("openstack-tenant-name")
	d.TenantId = flags.String("openstack-tenant-id")
	d.TenantDomainName = flags.String("openstack-tenant-domain-name")
	d.TenantDomainId = flags.String("openstack-tenant-domain-id")
	d.UserDomainName = flags.String("openstack-user-domain-name")
	d.UserDomainId = flags.String("openstack-user-domain-id")
	d.ApplicationCredentialId = flags.String("openstack-application-credential-id")
	d.ApplicationCredentialName = flags.String("openstack-application-credential-name")
	d.ApplicationCredentialSecret = flags.String("openstack-application-credential-secret")
	d.Region = flags.String("openstack-region")
	d.AvailabilityZone = flags.String("openstack-availability-zone")
	d.EndpointType = flags.String("openstack-endpoint-type")
	d.FlavorId = flags.String("openstack-flavor-id")
	d.FlavorName = flags.String("openstack-flavor-name")
	d.ImageId = flags.String("openstack-image-id")
	d.ImageName = flags.String("openstack-image-name")
	if flags.String("openstack-net-id") != "" {
		d.NetworkIds = strings.Split(flags.String("openstack-net-id"), ",")
	}
	if flags.String("openstack-net-name") != "" {
		d.NetworkNames = strings.Split(flags.String("openstack-net-name"), ",")
	}
	rawAllowedAddressPairs := flags.StringSlice("openstack-allowed-address-pairs")
	d.AllowedAddressPairs = make([]AllowedAddressPair, len(rawAllowedAddressPairs))
	for i, pair := range rawAllowedAddressPairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			d.AllowedAddressPairs[i] = AllowedAddressPair{IPAddress: parts[0], NetworkName: parts[1]}
		} else {
			d.AllowedAddressPairs[i] = AllowedAddressPair{IPAddress: parts[0], NetworkName: d.NetworkNames[0]}
		}
	}

	if flags.String("openstack-sec-groups") != "" {
		d.SecurityGroups = strings.Split(flags.String("openstack-sec-groups"), ",")
	}
	d.FloatingIpPool = flags.String("openstack-floatingip-pool")
	d.IpVersion = flags.Int("openstack-ip-version")
	d.ComputeNetwork = flags.Bool("openstack-nova-network")
	d.SSHUser = flags.String("openstack-ssh-user")
	d.SSHPort = flags.Int("openstack-ssh-port")
	d.ExistingKey = flags.String("openstack-keypair-name") != ""
	d.KeyPairName = flags.String("openstack-keypair-name")
	d.PrivateKeyFile = flags.String("openstack-private-key-file")
	d.ConfigDrive = flags.Bool("openstack-config-drive")

	d.BootFromVolume = flags.Bool("openstack-boot-from-volume")
	d.VolumeName = flags.String("openstack-volume-name")
	d.VolumeDevicePath = flags.String("openstack-volume-device-path")
	d.VolumeId = flags.String("openstack-volume-id")
	d.VolumeType = flags.String("openstack-volume-type")
	d.VolumeSize = flags.Int("openstack-volume-size")

	if flags.String("openstack-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("openstack-user-data-file"))
		if err == nil {
			d.UserData = userData
		} else {
			return err
		}
	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err
	}

	addressType := Fixed
	if d.FloatingIpPool != "" {
		addressType = Floating
	}

	// Looking for the IP address in a retry loop to deal with OpenStack latency
	for retryCount := 0; retryCount < 5; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err
		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("no IP found for the machine")
}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for OpenStack instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err
	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err
	}

	log.Debug("State for OpenStack instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) failedToCreate(err error) error {
	if e := d.Remove(); e != nil {
		return fmt.Errorf("%v: %v", err, e)
	}
	return err
}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err
	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err
		}
	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err
		}
	}
	if d.BootFromVolume == false && d.VolumeSize > 0 {
		if err := d.volumeCreate(); err != nil {
			return err
		}
	}
	log.Debug("Initiating instance creation...", map[string]string{
		"MachineName": d.MachineName,
		"FlavorId":    d.FlavorId,
		"ImageId":     d.ImageId,
	})
	if err := d.createMachine(); err != nil {
		return err
	}
	if err := d.waitForInstanceActive(); err != nil {
		return d.failedToCreate(err)
	}
	if d.BootFromVolume == false && d.VolumeId != "" {
		if err := d.waitForVolumeAvailable(); err != nil {
			return err
		}
		if err := d.volumeAttach(); err != nil {
			return err
		}
	}
	if d.FloatingIpPool != "" {
		if err := d.assignFloatingIP(); err != nil {
			return d.failedToCreate(err)
		}
	}
	if err := d.lookForIPAddress(); err != nil {
		return d.failedToCreate(err)
	}

	log.Info("OpenStack instance created successfully", map[string]string{
		"MachineId": d.MachineId,
		"IPAddress": d.IPAddress,
	})

	return nil
}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StartInstance(d)
}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StopInstance(d)
}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.RestartInstance(d)
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting OpenStack instance...")

	if err := d.resolveIds(); err != nil {
		return err
	}

	if d.FloatingIpPool != "" && d.IPAddress != "" && !d.ComputeNetwork {
		floatingIP, err := d.client.GetFloatingIP(d, d.IPAddress)
		if err != nil {
			return err
		}

		if floatingIP != nil {
			log.Debug("Deleting Floating IP: ", map[string]string{"floatingIP": floatingIP.Ip})
			if err := d.client.DeleteFloatingIP(d, floatingIP); err != nil {
				return err
			}
		}
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.DeleteInstance(d); err != nil {
		if gopherErr, ok := err.(*gophercloud.ErrUnexpectedResponseCode); ok {
			if gopherErr.Actual == http.StatusNotFound {
				log.Warn("Remote instance does not exist, proceeding with removing local reference")
			} else {
				return err
			}
		} else {
			return err
		}
	}
	if !d.ExistingKey {
		log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
		if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
			return err
		}
	}
	return nil
}

const (
	errorMandatoryEnvOrOption string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption      string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions     string = "Either %s or %s must be specified, not both"
	errorBothOptions          string = "Both %s and %s must be specified"
	errorWrongEndpointType    string = "Endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName    string = "Unable to find flavor named %s"
	errorUnknownImageName     string = "Unable to find image named %s"
	errorUnknownNetworkName   string = "Unable to find network named %s"
	errorUnknownTenantName    string = "Unable to find tenant named %s"
)

func (d *Driver) parseAuthConfig() (*gophercloud.AuthOptions, error) {
	return clientconfig.AuthOptions(
		&clientconfig.ClientOpts{
			// this is needed to disable the clientconfig.AuthOptions func env detection
			EnvPrefix: "_",
			AuthInfo: &clientconfig.AuthInfo{
				AuthURL:                     d.AuthUrl,
				UserID:                      d.UserId,
				Username:                    d.Username,
				Password:                    d.Password,
				ProjectID:                   d.TenantId,
				ProjectName:                 d.TenantName,
				DomainID:                    d.DomainId,
				DomainName:                  d.DomainName,
				ProjectDomainID:             d.TenantDomainId,
				ProjectDomainName:           d.TenantDomainName,
				UserDomainID:                d.UserDomainId,
				UserDomainName:              d.UserDomainName,
				ApplicationCredentialID:     d.ApplicationCredentialId,
				ApplicationCredentialName:   d.ApplicationCredentialName,
				ApplicationCredentialSecret: d.ApplicationCredentialSecret,
			},
		},
	)
}

func (d *Driver) checkConfig() error {
	if _, err := d.parseAuthConfig(); err != nil {
		return err
	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--openstack-flavor-name or --openstack-flavor-id")
	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")
	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--openstack-image-name or --openstack-image-id")
	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")
	}

	if len(d.NetworkNames) > 0 && len(d.NetworkIds) > 0 {
		return fmt.Errorf(errorExclusiveOptions, "Network name(s)", "Network id(s)")
	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)
	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")
	}
	return nil
}

func (d *Driver) resolveIds() error {
	if len(d.NetworkNames) > 0 && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}

		networkIDs, err := d.client.GetNetworkIDList(d)

		if err != nil {
			return err
		}

		if len(networkIDs) == 0 {
			return fmt.Errorf(errorUnknownNetworkName, d.NetworkNames)
		}

		d.NetworkIds = networkIDs
	}

	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err
		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)
		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})
	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err
		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)
		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})
	}

	if d.FloatingIpPool != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}
		f, err := d.client.GetFloatingIPPoolID(d)

		if err != nil {
			return err
		}

		if f == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.FloatingIpPool)
		}

		d.FloatingIpPoolId = f
		log.Debug("Found floating IP pool id using its name", map[string]string{
			"Name": d.FloatingIpPool,
			"ID":   d.FloatingIpPoolId,
		})
	}

	return nil
}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initBlockStorage() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitBlockStorageClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err
	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createMachine() error {
	log.Debug("Creating OpenStack instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err
	}

	if d.requiresBlockStorage() {
		if err := d.initBlockStorage(); err != nil {
			return err
		}
	}

	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err
	}
	d.MachineId = instanceID
	log.Debug("Machine created...", map[string]string{
		"MachineId":   d.MachineId,
		"MachineName": d.MachineName,
	})
	if err := d.client.AddAllowedAddressPairs(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) volumeCreate() error {
	if d.VolumeName == "" {
		d.VolumeName = "rancher-machine-volume"
	}
	log.Debug("Creating OpenStack Volume ...", map[string]string{
		"VolumeName": d.VolumeName,
		"VolumeType": d.VolumeType,
		"VolumeSize": strconv.Itoa(d.VolumeSize),
	})

	if err := d.initBlockStorage(); err != nil {
		return err
	}
	volumeId, err := d.client.VolumeCreate(d)
	if err != nil {
		return err
	}
	d.VolumeId = volumeId
	return nil
}

func (d *Driver) waitForVolumeAvailable() error {
	log.Debug("Waiting for the OpenStack volume to be available...", map[string]string{
		"VolumeId": d.VolumeId,
	})
	if err := d.initBlockStorage(); err != nil {
		return err
	}
	if err := d.client.WaitForVolumeStatus(d, "available"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) volumeAttach() error {
	log.Debug("Attaching OpenStack Volume ...", map[string]string{
		"VolumeId":         d.VolumeId,
		"VolumeDevicePath": d.VolumeDevicePath,
	})
	if err := d.initCompute(); err != nil {
		return err
	}
	VolumeDevicePath, err := d.client.VolumeAttach(d)
	if err != nil {
		return err
	}
	d.VolumeDevicePath = VolumeDevicePath
	return nil
}

func (d *Driver) assignFloatingIP() error {
	var err error

	if d.ComputeNetwork {
		err = d.initCompute()
	} else {
		err = d.initNetwork()
	}

	if err != nil {
		return err
	}

	floatingIP := &FloatingIP{}
	log.Debug("Allocating a new floating IP...", map[string]string{"MachineId": d.MachineId})

	if err := d.client.AssignFloatingIP(d, floatingIP); err != nil {
		return err
	}
	d.IPAddress = floatingIP.Ip
	return nil
}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the OpenStack instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil
}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

// openstack deployments may not have cinder available
// check to see if it's required before initializing
func (d *Driver) requiresBlockStorage() bool {
	return d.VolumeName != "" || d.VolumeId != "" || d.VolumeType != "" || d.BootFromVolume || d.VolumeSize > 0 || d.VolumeDevicePath != ""
}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)
}
