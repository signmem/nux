package nux

import (
	"fmt"
	"strings"
)

var FSSPEC_IGNORE = map[string]struct{}{
	"none":      struct{}{},
	"nodev":     struct{}{},
	"proc":      struct{}{},
	"hugetlbfs": struct{}{},
	"mqueue":    struct{}{},
}

var FSTYPE_IGNORE = map[string]struct{}{
	"cgroup":     struct{}{},
	"debugfs":    struct{}{},
	"devpts":     struct{}{},
	"devtmpfs":   struct{}{},
	"iso9660":    struct{}{},
	"rpc_pipefs": struct{}{},
	"rootfs":     struct{}{},
	"overlay":    struct{}{},
	"squashfs":   struct{}{},
        "autofs":     struct{}{},
        "ceph":       struct{}{},
        "configfs":   struct{}{},
        "mqueue":     struct{}{},
        "proc":       struct{}{},
        "pstore":     struct{}{},
        "securityfs": struct{}{},
        "sysfs":      struct{}{},
        "tmpfs":      struct{}{},
}

var FSFILE_PREFIX_IGNORE = []string{
	"/sys",
	"/net",
	"/misc",
	"/proc",
	"/lib",
        "/run",
        "/mnt",
}

func IgnoreFsFile(fs_file string) bool {
	for _, prefix := range FSFILE_PREFIX_IGNORE {
		if strings.HasPrefix(fs_file, prefix) {
			return true
		}
	}

	return false
}

type DeviceUsage struct {
	FsSpec            string
	FsFile            string
	FsVfstype         string
	BlocksAll         uint64
	BlocksUsed        uint64
	BlocksFree        uint64
	BlocksUsedPercent float64
	BlocksFreePercent float64
	InodesAll         uint64
	InodesUsed        uint64
	InodesFree        uint64
	InodesUsedPercent float64
	InodesFreePercent float64
}

func (this *DeviceUsage) String() string {
	return fmt.Sprintf("<FsSpec:%s, FsFile:%s, FsVfstype:%s, BPFree:%f...>",
		this.FsSpec,
		this.FsFile,
		this.FsVfstype,
		this.BlocksFreePercent)
}
