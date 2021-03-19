package provision

import (
	"fmt"
	"io/ioutil"

	"github.com/rancher/machine/libmachine/provision/pkgaction"
)

func WithCustomScript(provisioner Provisioner, customScriptPath string) error {
	if provisioner == nil {
		return nil
	}

	if err := provisioner.SetHostname(provisioner.GetDriver().GetMachineName()); err != nil {
		return err
	}

	for _, pkg := range provisioner.GetPackages() {
		if err := provisioner.Package(pkg, pkgaction.Install); err != nil {
			return err
		}
	}

	customScriptContents, err := ioutil.ReadFile(customScriptPath)
	if err != nil {
		return fmt.Errorf("unable to read file %s: %v", customScriptPath, err)
	}

	if output, err := provisioner.SSHCommand(fmt.Sprintf("echo \"%v\" | sh -", string(customScriptContents))); err != nil {
		return fmt.Errorf("error running custom script: output: %s, error: %s", output, err)
	}

	return nil
}
