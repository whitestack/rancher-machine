package provision

import (
	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/drivers"
	"github.com/rancher/machine/libmachine/engine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/provision/pkgaction"
	"github.com/rancher/machine/libmachine/provision/serviceaction"
	"github.com/rancher/machine/libmachine/swarm"
)

func init() {
	Register("Centos", &RegisteredProvisioner{
		New: NewCentosProvisioner,
	})
}

func NewCentosProvisioner(d drivers.Driver) Provisioner {
	return &CentosProvisioner{
		NewRedHatProvisioner("centos", d),
	}
}

type CentosProvisioner struct {
	*RedHatProvisioner
}

func (provisioner *CentosProvisioner) String() string {
	return "centos"
}

func (provisioner *CentosProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions
	swarmOptions.Env = engineOptions.Env

	storageDriver, err := decideStorageDriver(provisioner, DefaultStorageDriver, engineOptions.StorageDriver)
	if err != nil {
		return err
	}
	provisioner.EngineOptions.StorageDriver = storageDriver

	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	if err := installDockerGeneric(provisioner, provisioner.EngineOptions.InstallURL); err != nil {
		return err
	} else if err == nil {
		if err := provisioner.Service("docker", serviceaction.Restart); err != nil {
			return err
		}
		if err := provisioner.Service("docker", serviceaction.Enable); err != nil {
			return err
		}
	}

	for _, pkg := range provisioner.Packages {
		log.Debugf("installing base package: name=%s", pkg)
		if err := provisioner.Package(pkg, pkgaction.Install); err != nil {
			return err
		}
	}

	if err := mcnutils.WaitFor(provisioner.dockerDaemonResponding); err != nil {
		return err
	}

	if err := makeDockerOptionsDir(provisioner); err != nil {
		return err
	}

	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	if err := ConfigureAuth(provisioner); err != nil {
		return err
	}

	err = configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions)
	return err
}
