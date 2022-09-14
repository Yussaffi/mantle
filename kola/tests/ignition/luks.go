// Copyright The Mantle Authors
// Copyright 2020 Red Hat
// SPDX-License-Identifier: Apache-2.0
package ignition

import (
	"github.com/coreos/go-semver/semver"
	"github.com/flatcar/mantle/kola/cluster"
	"github.com/flatcar/mantle/kola/register"
	"github.com/flatcar/mantle/platform/conf"
)

func init() {
	register.Register(&register.Test{
		Name:        "cl.ignition.luks",
		Run:         luksTest,
		ClusterSize: 1,
		Distros:     []string{"cl"},
		// This test is normally not related to the cloud environment
		Platforms:  []string{"qemu", "qemu-unpriv"},
		MinVersion: semver.Version{Major: 3185},
		UserData: conf.Butane(`---
variant: flatcar
version: 1.0.0
storage:
  luks:
    - name: data
      device: /dev/disk/by-partlabel/USR-B
  filesystems:
    - path: /var/lib/data
      device: /dev/disk/by-id/dm-name-data
      format: ext4
      label: DATA
      with_mount_unit: true`),
	})
}

func luksTest(c cluster.TestCluster) {
	m := c.Machines()[0]

	c.MustSSH(m, "sudo cryptsetup isLuks /dev/disk/by-partlabel/USR-B")
	c.MustSSH(m, "systemctl is-active var-lib-data.mount")
}
