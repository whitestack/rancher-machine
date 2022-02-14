package provision

import (
	"github.com/rancher/machine/libmachine/drivers"
)

func init() {
	Register("Rocky", &RegisteredProvisioner{
		New: NewRockyProvisioner,
	})
}

func NewRockyProvisioner(d drivers.Driver) Provisioner {
	return &RockyProvisioner{
		NewRedHatProvisioner("rocky", d),
	}
}

type RockyProvisioner struct {
	*RedHatProvisioner
}

func (provisioner *RockyProvisioner) String() string {
	return "rocky"
}
