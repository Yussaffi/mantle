// Copyright 2017 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package misc

import (
	"encoding/json"
	"fmt"

	"github.com/flatcar/mantle/kola/cluster"
	"github.com/flatcar/mantle/kola/register"
	"github.com/flatcar/mantle/kola/tests/util"
	"github.com/flatcar/mantle/platform"
	"github.com/flatcar/mantle/platform/conf"
	"github.com/flatcar/mantle/platform/machine/qemu"
	"github.com/flatcar/mantle/platform/machine/unprivqemu"
)

const (
	IgnitionConfigRootRaid = `{
  "ignition": {
    "config": {},
    "security": {
      "tls": {}
    },
    "timeouts": {},
    "version": "2.3.0"
  },
  "networkd": {},
  "storage": {
    "disks": [
      {
        "device": "/dev/disk/by-id/virtio-secondary",
        "partitions": [
          {
            "label": "root1",
            "number": 1,
            "sizeMiB": 256,
            "typeGuid": "be9067b9-ea49-4f15-b4f6-f36f8c9e1818"
          },
          {
            "label": "root2",
            "number": 2,
            "sizeMiB": 256,
            "typeGuid": "be9067b9-ea49-4f15-b4f6-f36f8c9e1818"
          }
        ],
        "wipeTable": true
      }
    ],
    "filesystems": [
      {
        "mount": {
          "device": "/dev/md/rootarray",
          "format": "ext4",
          "label": "ROOT"
        },
        "name": "ROOT"
      },
      {
        "mount": {
          "device": "/dev/disk/by-id/virtio-primary-disk-part9",
          "format": "ext4",
          "label": "wasteland",
          "wipeFilesystem": true
        },
        "name": "NOT_ROOT"
      }
    ],
    "raid": [
      {
        "devices": [
          "/dev/disk/by-partlabel/root1",
          "/dev/disk/by-partlabel/root2"
        ],
        "level": "{{ .RaidLevel }}",
        "name": "rootarray"
      }
    ]
  }
}
`

	IgnitionConfigDataRaid = `{
  "ignition": {
    "config": {},
    "security": {
      "tls": {}
    },
    "timeouts": {},
    "version": "2.3.0"
  },
  "networkd": {},
  "storage": {
    "disks": [
      {
        "device": "/dev/disk/by-partlabel/OEM-CONFIG"
      },
      {
        "device": "/dev/disk/by-partlabel/USR-B"
      }
    ],
    "filesystems": [
      {
        "name": "DATA",
        "mount": {
          "device": "/dev/md/DATA",
          "format": "ext4",
          "label": "DATA"
        }
      }
    ],
    "raid": [
      {
        "devices": [
          "/dev/disk/by-partlabel/OEM-CONFIG",
          "/dev/disk/by-partlabel/USR-B"
        ],
        "level": "{{ .RaidLevel }}",
        "name": "DATA"
      }
    ]
  },
  "systemd": {
    "units": [
      {
        "name": "var-lib-data.mount",
        "enabled": true,
        "contents": "[Mount]\nWhat=/dev/md/DATA\nWhere=/var/lib/data\nType=ext4\n\n[Install]\nWantedBy=local-fs.target"
      }
    ]
  }
}
`
)

var (
	raidTypes = map[string]interface{}{
		"raid0": struct{}{},
		"raid1": struct{}{},
	}
)

type raidConfig struct {
	RaidLevel string
}

func init() {
	for raidLevel, _ := range raidTypes {
		level := raidLevel

		// root partition
		templRoot, err := util.ExecTemplate(IgnitionConfigRootRaid, raidConfig{
			RaidLevel: level,
		})
		if err != nil {
			fmt.Printf("fail to execute template for %s: %v\n", level, err)
			return
		}
		userDataRoot := conf.Ignition(templRoot)

		runRootOnRaid := func(c cluster.TestCluster) {
			RootOnRaid(c, userDataRoot)
		}

		register.Register(&register.Test{
			// This test needs additional disks which is only supported on qemu since Ignition
			// does not support deleting partitions without wiping the partition table and the
			// disk doesn't have room for new partitions.
			// TODO(ajeddeloh): change this to delete partition 9 and replace it with 9 and 10
			// once Ignition supports it.
			Run:         runRootOnRaid,
			ClusterSize: 0,
			// This test is normally not related to the cloud environment
			Platforms: []string{"qemu"},
			Name:      fmt.Sprintf("cl.disk.%s.root", raidLevel),
			Distros:   []string{"cl"},
		})

		// data partition
		templData, err := util.ExecTemplate(IgnitionConfigDataRaid, raidConfig{
			RaidLevel: level,
		})
		if err != nil {
			fmt.Printf("fail to execute template for %s: %v\n", level, err)
			return
		}
		userDataData := conf.Ignition(templData)

		runDataOnRaid := func(c cluster.TestCluster) {
			DataOnRaid(c, userDataData)
		}

		register.Register(&register.Test{
			Run:         runDataOnRaid,
			ClusterSize: 1,
			Name:        fmt.Sprintf("cl.disk.%s.data", raidLevel),
			UserData:    userDataData,
			Distros:     []string{"cl"},
			// This test is normally not related to the cloud environment
			Platforms: []string{"qemu", "qemu-unpriv"},
		})
	}
}

func RootOnRaid(c cluster.TestCluster, userData *conf.UserData) {
	var m platform.Machine
	var err error
	options := platform.MachineOptions{
		AdditionalDisks: []platform.Disk{
			{Size: "520M", DeviceOpts: []string{"serial=secondary"}},
		},
	}
	switch pc := c.Cluster.(type) {
	// These cases have to be separated because when put together to the same case statement
	// the golang compiler no longer checks that the individual types in the case have the
	// NewMachineWithOptions function, but rather whether platform.Cluster does which fails
	case *qemu.Cluster:
		m, err = pc.NewMachineWithOptions(userData, options)
	case *unprivqemu.Cluster:
		m, err = pc.NewMachineWithOptions(userData, options)
	default:
		c.Fatal("unknown cluster type")
	}
	if err != nil {
		c.Fatal(err)
	}

	checkIfMountpointIsRaid(c, m, "/")

	// reboot it to make sure it comes up again
	err = m.Reboot()
	if err != nil {
		c.Fatalf("could not reboot machine: %v", err)
	}

	checkIfMountpointIsRaid(c, m, "/")
}

func DataOnRaid(c cluster.TestCluster, userData *conf.UserData) {
	m := c.Machines()[0]

	checkIfMountpointIsRaid(c, m, "/var/lib/data")

	// reboot it to make sure it comes up again
	err := m.Reboot()
	if err != nil {
		c.Fatalf("could not reboot machine: %v", err)
	}

	checkIfMountpointIsRaid(c, m, "/var/lib/data")
}

type lsblkOutput struct {
	Blockdevices []blockdevice `json:"blockdevices"`
}

type blockdevice struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Mountpoint *string `json:"mountpoint"`
	// Mountpoints holds all mountpoints relevant for the device
	// it aims to replace `Mountpoint` from util-linux-2.37.
	Mountpoints []string      `json:"mountpoints"`
	Children    []blockdevice `json:"children"`
}

// checkIfMountpointIsRaid will check if a given machine has a device of type
// raid1 mounted at the given mountpoint. If it does not, the test is failed.
func checkIfMountpointIsRaid(c cluster.TestCluster, m platform.Machine, mountpoint string) {
	output := c.MustSSH(m, "lsblk --json")

	l := lsblkOutput{}
	err := json.Unmarshal(output, &l)
	if err != nil {
		c.Fatalf("couldn't unmarshal lsblk output: %v", err)
	}

	foundRoot := checkIfMountpointIsRaidWalker(c, l.Blockdevices, mountpoint)
	if !foundRoot {
		c.Fatalf("didn't find root mountpoint in lsblk output")
	}
}

// checkIfMountpointIsRaidWalker will iterate over bs and recurse into its
// children, looking for a device mounted at / with type raid1. true is returned
// if such a device is found. The test is failed if a device of a different type
// is found to be mounted at /.
func checkIfMountpointIsRaidWalker(c cluster.TestCluster, bs []blockdevice, mountpoint string) bool {
	for _, b := range bs {
		// >= util-linux-2.37
		for _, mnt := range b.Mountpoints {
			if mnt == mountpoint && isValidRaidType(b.Type) {
				return true
			}
		}

		if b.Mountpoint != nil && *b.Mountpoint == mountpoint {
			if !isValidRaidType(b.Type) {
				c.Fatalf("invalid raid type, device %q is mounted at %q with type %q", b.Name, mountpoint, b.Type)
			}
			return true
		}
		foundRoot := checkIfMountpointIsRaidWalker(c, b.Children, mountpoint)
		if foundRoot {
			return true
		}
	}
	return false
}

// isValidRaidType checks if the given type string is one of the possible
// RAID types supported by the testsuite. For example, raid0 or raid1.
func isValidRaidType(rType string) bool {
	if _, ok := raidTypes[rType]; ok {
		return true
	}
	return false
}
