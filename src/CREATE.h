#include "events.h"
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/d_instantiate")
int BPF_PROG(watchd_d_instantiate, struct dentry *dentry, struct inode *inode) {

  struct KEY key = {};
  struct EVENT *transaction;
  struct task_struct *task;
  __u32 *val;

  // make key
  key.inode_number = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);
  key.dev_id = BPF_CORE_READ(dentry, d_parent, d_inode, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);

  if (!val)
    return 0;

  return 0
}
