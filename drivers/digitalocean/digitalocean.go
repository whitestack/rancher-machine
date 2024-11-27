package digitalocean

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"
	"golang.org/x/oauth2"
)

type Driver struct {
	*drivers.BaseDriver
	AccessToken       string
	DropletID         int
	DropletName       string
	Image             string
	Region            string
	SSHKeyID          int
	SSHKeyFingerprint string
	SSHKey            string
	Size              string
	IPv6              bool
	Backups           bool
	PrivateNetworking bool
	UserDataFile      string
	Monitoring        bool
	Tags              string
	PrivateIPAddress  string
}

const (
	defaultSSHPort = 22
	defaultSSHUser = "root"
	defaultImage   = "ubuntu-20-04-x64"
	defaultRegion  = "nyc3"
	defaultSize    = "s-1vcpu-1gb"
)

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_ACCESS_TOKEN",
			Name:   "digitalocean-access-token",
			Usage:  "Digital Ocean access token",
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_SSH_USER",
			Name:   "digitalocean-ssh-user",
			Usage:  "SSH username",
			Value:  defaultSSHUser,
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_SSH_KEY_FINGERPRINT",
			Name:   "digitalocean-ssh-key-fingerprint",
			Usage:  "SSH key fingerprint",
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_SSH_KEY_PATH",
			Name:   "digitalocean-ssh-key-path",
			Usage:  "SSH private key path ",
		},
		mcnflag.IntFlag{
			EnvVar: "DIGITALOCEAN_SSH_PORT",
			Name:   "digitalocean-ssh-port",
			Usage:  "SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_IMAGE",
			Name:   "digitalocean-image",
			Usage:  "Digital Ocean Image",
			Value:  defaultImage,
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_REGION",
			Name:   "digitalocean-region",
			Usage:  "Digital Ocean region",
			Value:  defaultRegion,
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_SIZE",
			Name:   "digitalocean-size",
			Usage:  "Digital Ocean size",
			Value:  defaultSize,
		},
		mcnflag.BoolFlag{
			EnvVar: "DIGITALOCEAN_IPV6",
			Name:   "digitalocean-ipv6",
			Usage:  "enable ipv6 for droplet",
		},
		mcnflag.BoolFlag{
			EnvVar: "DIGITALOCEAN_PRIVATE_NETWORKING",
			Name:   "digitalocean-private-networking",
			Usage:  "enable private networking for droplet",
		},
		mcnflag.BoolFlag{
			EnvVar: "DIGITALOCEAN_BACKUPS",
			Name:   "digitalocean-backups",
			Usage:  "enable backups for droplet",
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_USERDATA",
			Name:   "digitalocean-userdata",
			Usage:  "path to file with cloud-init user-data",
		},
		mcnflag.BoolFlag{
			EnvVar: "DIGITALOCEAN_MONITORING",
			Name:   "digitalocean-monitoring",
			Usage:  "enable monitoring for droplet",
		},
		mcnflag.StringFlag{
			EnvVar: "DIGITALOCEAN_TAGS",
			Name:   "digitalocean-tags",
			Usage:  "comma-separated list of tags to apply to the Droplet",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		Image:  defaultImage,
		Size:   defaultSize,
		Region: defaultRegion,
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "digitalocean"
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
	if _, ok := driverOpts.Values["digitalocean-access-token"]; ok {
		d.AccessToken = driverOpts.String("digitalocean-access-token")
	}

	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AccessToken = flags.String("digitalocean-access-token")
	d.Image = flags.String("digitalocean-image")
	d.Region = flags.String("digitalocean-region")
	d.Size = flags.String("digitalocean-size")
	d.IPv6 = flags.Bool("digitalocean-ipv6")
	d.PrivateNetworking = flags.Bool("digitalocean-private-networking")
	d.Backups = flags.Bool("digitalocean-backups")
	d.UserDataFile = flags.String("digitalocean-userdata")
	d.SSHUser = flags.String("digitalocean-ssh-user")
	d.SSHPort = flags.Int("digitalocean-ssh-port")
	d.SSHKeyFingerprint = flags.String("digitalocean-ssh-key-fingerprint")
	d.SSHKey = flags.String("digitalocean-ssh-key-path")
	d.Monitoring = flags.Bool("digitalocean-monitoring")
	d.Tags = flags.String("digitalocean-tags")

	d.SetSwarmConfigFromFlags(flags)

	if d.AccessToken == "" {
		return fmt.Errorf("digitalocean driver requires the --digitalocean-access-token option")
	}

	return nil
}

func (d *Driver) PreCreateCheck() error {
	if d.UserDataFile != "" {
		if _, err := os.Stat(d.UserDataFile); os.IsNotExist(err) {
			return fmt.Errorf("user-data file %s could not be found", d.UserDataFile)
		}
	}

	if d.SSHKey != "" {
		if d.SSHKeyFingerprint == "" {
			return fmt.Errorf("ssh-key-fingerprint needs to be provided for %q", d.SSHKey)
		}

		if _, err := os.Stat(d.SSHKey); os.IsNotExist(err) {
			return fmt.Errorf("SSH key does not exist: %q", d.SSHKey)
		}
	}

	client := d.getClient()
	regions, _, err := client.Regions.List(context.TODO(), nil)
	if err != nil {
		return err
	}
	for _, region := range regions {
		if region.Slug == d.Region {
			return nil
		}
	}

	return fmt.Errorf("digitalocean requires a valid region")
}

func (d *Driver) Create() error {
	var userdata string
	if d.UserDataFile != "" {
		buf, err := os.ReadFile(d.UserDataFile)
		if err != nil {
			return err
		}
		userdata = string(buf)
	}

	log.Infof("Creating SSH key...")

	key, err := d.createSSHKey()
	if err != nil {
		return err
	}

	d.SSHKeyID = key.ID

	log.Infof("Creating Digital Ocean droplet...")

	client := d.getClient()

	createRequest := &godo.DropletCreateRequest{
		Image:             godo.DropletCreateImage{Slug: d.Image},
		Name:              d.MachineName,
		Region:            d.Region,
		Size:              d.Size,
		IPv6:              d.IPv6,
		PrivateNetworking: d.PrivateNetworking,
		Backups:           d.Backups,
		UserData:          userdata,
		SSHKeys:           []godo.DropletCreateSSHKey{{ID: d.SSHKeyID}},
		Monitoring:        d.Monitoring,
		Tags:              d.getTags(),
	}

	newDroplet, _, err := client.Droplets.Create(context.TODO(), createRequest)
	if err != nil {
		return err
	}

	d.DropletID = newDroplet.ID

	log.Info("Waiting for IP address to be assigned to the Droplet...")
	for {
		newDroplet, _, err = client.Droplets.Get(context.TODO(), d.DropletID)
		if err != nil {
			if removeErr := d.Remove(); removeErr != nil {
				return fmt.Errorf("failed to create machine due to error: %v. Removing droplets: %v", err, removeErr)
			}
			return err
		}
		for _, network := range newDroplet.Networks.V4 {
			if network.Type == "public" {
				d.IPAddress = network.IPAddress
			}
			if d.PrivateNetworking && network.Type == "private" {
				d.PrivateIPAddress = network.IPAddress
			}
		}

		if d.IPAddress != "" && (!d.PrivateNetworking || d.PrivateIPAddress != "") {
			break
		}

		time.Sleep(5 * time.Second)
	}

	log.Debugf("Created droplet ID %d, IP address %s, Private IP address %s",
		newDroplet.ID,
		d.IPAddress,
		d.PrivateIPAddress)

	return nil
}

func (d *Driver) createSSHKey() (*godo.Key, error) {
	d.SSHKeyPath = d.GetSSHKeyPath()

	if d.SSHKeyFingerprint != "" {
		key, resp, err := d.getClient().Keys.GetByFingerprint(context.TODO(), d.SSHKeyFingerprint)
		if err != nil && resp.StatusCode == 404 {
			return nil, fmt.Errorf("Digital Ocean SSH key with fingerprint %s doesn't exist", d.SSHKeyFingerprint)
		}

		if d.SSHKey == "" {
			log.Infof("Assuming Digital Ocean private SSH is located at ~/.ssh/id_rsa")
			return key, nil
		}

		if err := copySSHKey(d.SSHKey, d.SSHKeyPath); err != nil {
			return nil, err
		}
		return key, nil
	}

	if err := ssh.GenerateSSHKey(d.SSHKeyPath); err != nil {
		return nil, err
	}

	publicKey, err := os.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return nil, err
	}

	createRequest := &godo.KeyCreateRequest{
		Name:      d.MachineName,
		PublicKey: string(publicKey),
	}

	key, _, err := d.getClient().Keys.Create(context.TODO(), createRequest)
	if err != nil {
		return key, err
	}

	return key, nil
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetState() (state.State, error) {
	droplet, resp, err := d.getClient().Droplets.Get(context.TODO(), d.DropletID)
	if err != nil {
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			return state.Error, err
		}
		return state.None, fmt.Errorf("machine %v not found", d.MachineName)
	}

	switch droplet.Status {
	case "new":
		return state.Starting, nil
	case "active":
		return state.Running, nil
	case "off":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) Start() error {
	_, _, err := d.getClient().DropletActions.PowerOn(context.TODO(), d.DropletID)
	return err
}

func (d *Driver) Stop() error {
	_, _, err := d.getClient().DropletActions.Shutdown(context.TODO(), d.DropletID)
	return err
}

func (d *Driver) Restart() error {
	_, _, err := d.getClient().DropletActions.Reboot(context.TODO(), d.DropletID)
	return err
}

func (d *Driver) Kill() error {
	_, _, err := d.getClient().DropletActions.PowerOff(context.TODO(), d.DropletID)
	return err
}

func (d *Driver) Remove() error {
	client := d.getClient()
	if d.SSHKeyFingerprint == "" && d.SSHKeyID != 0 {
		if resp, err := client.Keys.DeleteByID(context.TODO(), d.SSHKeyID); err != nil {
			if resp.StatusCode == 404 {
				log.Infof("Digital Ocean SSH key doesn't exist, assuming it is already deleted")
			} else {
				return err
			}
		}
	}
	if resp, err := client.Droplets.Delete(context.TODO(), d.DropletID); err != nil {
		if resp != nil && resp.StatusCode == 404 {
			log.Infof("Digital Ocean droplet doesn't exist, assuming it is already deleted")
		} else {
			log.Errorf("ERROR: %v", err)
			return err
		}
	}
	return nil
}

func (d *Driver) getClient() *godo.Client {
	token := &oauth2.Token{AccessToken: d.AccessToken}
	tokenSource := oauth2.StaticTokenSource(token)
	client := oauth2.NewClient(oauth2.NoContext, tokenSource)

	return godo.NewClient(client)
}

func (d *Driver) getTags() []string {
	var tagList []string

	for _, t := range strings.Split(d.Tags, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tagList = append(tagList, t)
		}
	}

	return tagList
}

func (d *Driver) GetSSHKeyPath() string {
	if d.SSHKey != "" {
		d.SSHKeyPath = d.ResolveStorePath(path.Base(d.SSHKey))
	} else if d.SSHKeyPath == "" && d.SSHKeyFingerprint == "" {
		d.SSHKeyPath = d.ResolveStorePath("id_rsa")
	}
	return d.SSHKeyPath
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func copySSHKey(src, dst string) error {
	if err := mcnutils.CopyFile(src, dst); err != nil {
		return fmt.Errorf("unable to copy ssh key: %s", err)
	}

	if err := os.Chmod(dst, 0600); err != nil {
		return fmt.Errorf("unable to set permissions on the ssh key: %s", err)
	}

	return nil
}
