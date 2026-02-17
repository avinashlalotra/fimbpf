
#include "mtypes.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define POLICY_MAX_ENTRIES 4000
#define EVENTS_MAX_ENTRIES 1 << 22
#define DIR_SIZE 4096

/* policy table */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, POLICY_MAX_ENTRIES);
  __type(key, struct KEY);
  __type(value, struct VALUE);
} policy_table SEC(".maps");

/* Circular ring buffer */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, EVENTS_MAX_ENTRIES);
} events SEC(".maps");

/* File Size Map */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __s64);
} file_size_map SEC(".maps");
