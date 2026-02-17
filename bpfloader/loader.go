// Package bpfInterface provides the interface between the kernel-space eBPF
// programs and the user-space Go application.
//
// It manages loading eBPF objects, updating BPF maps, and attaching
// LSM and tracing hooks required for filesystem monitoring
package bpfloader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TrackedFileKey uniquely identifies a file in the tracked file map.
//
// A file is identified using its inode number and device ID.
type TrackedFileKey struct {
	Inode_number uint64 // Inode_number is the inode number of the file.
	Dev          uint64 // Dev is the device ID on which the file resides.
}

// TrackedFileValue represents the value stored in the tracked file map.
type TrackedFileValue struct {
	Val uint8 // Val indicates whether the file is being tracked (1 = tracked).
}

// TrackedFile represents a single key-value pair in the tracked file map.
type TrackedFile struct {
	Key   TrackedFileKey
	Value TrackedFileValue
}

// TrackedFileMap represents the Go equivalent of the eBPF hash map
// (BPF_MAP_TYPE_HASH) used as the tracked file map.
//
// The map stores metadata about files that should be tracked.
// Files are uniquely identified by inode number and device ID.
type TrackedFileMap map[TrackedFileKey]TrackedFileValue

// Event represents the go equivalent of event struct od eBPF C program.
// It should have same memory layout as of it.
//
// It stores all the metadata which seemed to important for the application.
// It should be further processed to a friendly format
type FileChangeEvent struct {
	ParentInodeNumber uint64
	ParentDev         uint64

	InodeNumber uint64
	Dev         uint64

	Uid uint32
	Gid uint32

	ChangeType uint64
	Mtime      int64

	TtyIndex uint32
	TtyMajor int32

	FileSize   int64
	BeforeSize int64
	AfterSize  int64

	Filename [255]byte
}

// BPF abstracts the generated Go bindings for the compiled eBPF programs
// and maps. It provides helper methods for loading programs, attaching
// hooks, and interacting with BPF maps.
type BPF struct {
	Objects *fimObjects
	Load    func(interface{}, *ebpf.CollectionOptions) error
}

// InitBPF initializes and returns a new BPF instance.
//
// It prepares the object container and assigns the generated loader
// function used to load eBPF programs and maps into the kernel
func InitBPF() *BPF {
	return &BPF{
		Objects: &fimObjects{},
		Load:    loadFimObjects,
	}
}

// UpdateLookupTable updates the eBPF policy table based on a file change event.
//
// If the event indicates file creation (ChangeType == 1), the corresponding
// inode and device ID are inserted into the policy table.
//
// If the event indicates file deletion (ChangeType == 3), the corresponding
// entry is removed from the policy table.
func (b *BPF) UpdateLookupTable(event *FileChangeEvent) {

	key := TrackedFileKey{
		Inode_number: event.InodeNumber,
		Dev:          event.Dev,
	}

	value := TrackedFileValue{
		Val: 1,
	}

	// create
	if event.ChangeType == 1 {
		b.Objects.PolicyTable.Put(key, value)
	}

	// delete
	if event.ChangeType == 3 {
		b.Objects.PolicyTable.Delete(key)
	}

}

// AttachPrograms attaches all required LSM and tracing eBPF programs
// to their respective kernel hook points.
//
// It returns a slice of successfully attached links. If no programs
// are successfully attached, an aggregated error describing all
// attachment failures is returned.
func (b *BPF) AttachPrograms() ([]link.Link, error) {
	links := make([]link.Link, 0, 5)
	var err string

	attachLSM := func(prog *ebpf.Program, name string) {
		l, linkErr := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if linkErr != nil {
			err += fmt.Sprintf("ERROR attaching %s: %v \n", name, linkErr)
			return
		}
		links = append(links, l)
	}

	attachTracing := func(prog *ebpf.Program, name string) {
		l, linkErr := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		if linkErr != nil {
			err += fmt.Sprintf("ERROR attaching %s: %v\n", name, linkErr)
			return
		}
		links = append(links, l)
	}

	// LSM Hooks
	attachLSM(b.Objects.InodeInitSecurityHook, "inode_create hook")
	attachLSM(b.Objects.PathRmdirHook, "path_rmdir hook")
	attachLSM(b.Objects.PathUnlinkHook, "path_unlink hook")

	// Tracing Hooks
	attachTracing(b.Objects.VfsWriteEntryHook, "vfs_write entry hook")
	attachTracing(b.Objects.VfsWriteHook, "vfs_write hook")

	// If None is loaded then error
	for _, link := range links {
		if link != nil {
			return links, nil
		}
	}

	return nil, errors.New(err)
}
