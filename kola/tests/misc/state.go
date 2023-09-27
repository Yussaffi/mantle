// Copyright The Mantle Authors.
// SPDX-License-Identifier: Apache-2.0

package misc

import (
	"fmt"

	"github.com/coreos/go-semver/semver"

	"github.com/flatcar/mantle/kola/cluster"
	"github.com/flatcar/mantle/kola/register"
	"github.com/flatcar/mantle/platform/conf"
)

var (
	ignitionRerun = conf.Butane(`---
variant: flatcar
version: 1.0.0
storage:
  files:
  - path: /file-works
    contents:
      inline: "something"
systemd:
  units:
    - name: test.service
      enabled: true
      contents: |
        [Service]
        Type=oneshot
        RemainAfterExit=true
        ExecStart=touch /service-works
        [Install]
        WantedBy=multi-user.target
`)
)

func init() {
	register.Register(&register.Test{
		Run:         OverlayCleanup,
		ClusterSize: 1,
		Name:        "cl.overlay.cleanup",
		Distros:     []string{"cl"},
		MinVersion:  semver.Version{Major: 3530},
		// This test is normally not related to the cloud environment
		Platforms: []string{"qemu", "qemu-unpriv"},
	})
	register.Register(&register.Test{
		Run:         OsReset,
		ClusterSize: 1,
		Name:        "cl.osreset.ignition-rerun",
		UserData:    ignitionRerun,
		Distros:     []string{"cl"},
		MinVersion:  semver.Version{Major: 3530},
		// This test is normally not related to the cloud environment
		Platforms: []string{"qemu", "qemu-unpriv"},
	})
}

// Check that the overlay doesn't have unexpected upcopies, e.g., due to
// systemd-tmpfiles recreating the files/dirs or similar. Also check
// that duplicates get removed on reboot.
func OverlayCleanup(c cluster.TestCluster) {
	m := c.Machines()[0]

	// While we use systemd-tmpfiles to set up /etc contents during the image build, we don't expect
	// systemd-tmpfiles to cause any recreation at boot: This was observed with C, L, and d entries
	// (file or tree copy, symlink setup, directory creation) and thus they are dropped during image
	// build as workaround.
	overlayCheck := `sudo unshare -m bash -c 'umount /etc || { echo "Could not unmount /etc"; exit 1; }; if test -e "/etc/hosts" || test -e "/etc/security" || test -e "/etc/profile.d" || test -e "/etc/shells" || test -e "/etc/os-release" ; then echo "Unexpected overlay copy in /etc %s: $_" ; exit 1; fi'`
	_ = c.MustSSH(m, fmt.Sprintf(overlayCheck, "on initial boot"))

	// Do some local modifications that are expected to be kept:
	// special cases are recreating a directory but empty, deleting a file, deleting a directory,
	// and recreating a directory with same contents plus a new file.
	// /etc/sssd should have the same permissions but the only difference is that the overlay
	// will add the overlay.opaque xattr, /etc/samba is an empty directory in case of samba <= 4.15,
	// but the test would also be valid if it had contents, /etc/bash/bashrc must exist for the test
	// to work and the contents should get frozen and not touched by the cleanup because here we
	// recreate the folder (and add a new file in it) which means that the lowerdir folder isn't used
	// and deleting equal contents would not result in it being available.
	// All these files should not be part of the tmpfiles rules for the test to work.
	_ = c.MustSSH(m, `sudo rm -r /etc/sssd && sudo mkdir /etc/sssd && sudo chmod 700 /etc/sssd && sudo rm /etc/kexec.conf && sudo rm -rf /etc/samba && sudo rm -r /etc/bash && sudo cp -a /usr/share/flatcar/etc/bash /etc/bash && sudo touch /etc/bash/hello`)

	// The migration path for old machines with a full /etc and the cleanup of unwanted duplicates/
	// upcopies can be tested the same way by copying duplicates to /etc and then rebooting to
	// check that they get cleaned up.
	_ = c.MustSSH(m, `sudo unshare -m bash -c 'umount /etc && cp -a /usr/share/flatcar/etc/{hosts,shells,os-release} /etc/ && mkdir /etc/security /etc/profile.d'`)
	if err := m.Reboot(); err != nil {
		c.Fatalf("could not reboot: %v", err)
	}

	_ = c.MustSSH(m, fmt.Sprintf(overlayCheck, "after reboot"))
	_ = c.MustSSH(m, `if sudo test -e /etc/sssd/sssd.conf || test -e /etc/kexec.conf || test -e /etc/samba || test ! -e /etc/bash/hello || test ! -e /etc/bash/bashrc ; then echo "Deletion or modification lost: $_" ; exit 1; fi`)
}

// Check the OS reset logic with flatcar-reset to be able to
// reprovision the system while preserving selected paths.
func OsReset(c cluster.TestCluster) {
	m := c.Machines()[0]

	ignitionCheck := `sudo systemctl start test && if ! systemctl is-enabled -q test.service || test ! -e /service-works || test ! -e /file-works; then echo "Missing service/file %s: $_"; exit 1; fi`
	_ = c.MustSSH(m, fmt.Sprintf(ignitionCheck, "on initial boot"))

	prevMachineId := string(c.MustSSH(m, `cat /etc/machine-id`))

	// Create some local state to discard and to preserve, covering cases
	// where a file in a folder should be preserved and another not, or where
	// a folder should be preserved with a file in it to keep
	_ = c.MustSSH(m, `sudo rm /file-works && sudo mkdir /etc/custom /etc/keep-dir /etc/delete-dir && sudo touch /etc/delete-me /etc/keep-me /etc/keep-dir/file /etc/custom/delete-me /etc/custom/keep-me /etc/delete-dir/test`)

	// Will reuse the original Ignition config but we could also specify a new one
	_ = c.MustSSH(m, `sudo flatcar-reset --keep-machine-id --keep-paths '/etc/keep-dir' '/etc/keep-me' '/etc/custom/keep.*' '/var/log'`)
	if err := m.Reboot(); err != nil {
		c.Fatalf("could not reboot: %v", err)
	}
	// Check that Ignition reran
	_ = c.MustSSH(m, fmt.Sprintf(ignitionCheck, "after reset"))

	// Check that the local state is as expected
	_ = c.MustSSH(m, `if test ! -e /etc/keep-dir/file || test ! -e /etc/custom/keep-me || test ! -e /etc/keep-me || test -e /etc/delete-me || test -e /etc/custom/delete-me || test -e /etc/delete-dir ; then echo "Unexpected state: $_" exit 1; fi`)

	newMachineID := string(c.MustSSH(m, `cat /etc/machine-id`))
	if prevMachineId != newMachineID {
		c.Fatalf("machine ID not preserved: %q != %q", prevMachineId, newMachineID)
	}
}
