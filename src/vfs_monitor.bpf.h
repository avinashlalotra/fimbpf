#ifndef VM_MONITOR_H
#define VM_MONITOR_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


#define MAX_ENTRIES 200

struct policy_key  {
	__u64 inode_number;
	__u32  dev_id;
};

struct policy_value {
	__u32 mode;
	__u32 uid;
	__u32 gid;
	__u32 size;
	__u32 mtime;
	__u64 ctime;
	__u64 atime;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} policy_table SEC(".maps");

#endif
