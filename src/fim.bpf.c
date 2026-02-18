
#include "maps.h"
#include "mtypes.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

//----------------------------------- CREATE FILE
//---------------------------------
SEC("lsm/inode_create")
int BPF_PROG(watchd_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode) {
  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  struct inode *inode;
  __u64 uid_gid;

  // parent key
  key.inode = BPF_CORE_READ(dir, i_ino);
  key.dev = BPF_CORE_READ(dir, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  inode = BPF_CORE_READ(dentry, d_inode);
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->parent_dev = key.dev;
  event->parent_inode_number = key.inode;

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = CREATE;

  event->before_size = 0;
  event->after_size = 0; // new file starts empty

  event->inode_number = BPF_CORE_READ(inode, i_ino);
  event->dev = BPF_CORE_READ(inode, i_sb, s_dev);

  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);

  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

//----------------------------------- CREATE DIR
//---------------------------------
SEC("lsm/inode_mkdir")
int BPF_PROG(watchd_inode_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode) {
  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  struct inode *inode;
  __u64 uid_gid;

  key.inode = BPF_CORE_READ(dir, i_ino);
  key.dev = BPF_CORE_READ(dir, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode)
    return 0;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->parent_dev = key.dev;
  event->parent_inode_number = key.inode;

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = CREATE;

  event->before_size = 0;
  event->after_size = DIR_SIZE; // your constant for directory

  event->inode_number = BPF_CORE_READ(inode, i_ino);
  event->dev = BPF_CORE_READ(inode, i_sb, s_dev);

  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);

  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

//------------------------------------ DELETE ---------------------------------
// For files
SEC("lsm/inode_unlink")
int BPF_PROG(watchd_inode_unlink, struct inode *dir, struct dentry *dentry) {

  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  umode_t mode;
  __u64 uid_gid;

  // make key
  key.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  key.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  // delete from policy table
  bpf_map_delete_elem(&policy_table, &key);

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
  event->parent_inode_number = BPF_CORE_READ(dir, i_ino);

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = DELETE;
  event->before_size = val->file_size;
  event->after_size = 0;

  // populate rest of the event structure

  event->inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);
  event->dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);
  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);

  // submit event to ring buffer
  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(watchd_inode_rmdir, struct inode *dir, struct dentry *dentry) {

  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  umode_t mode;
  __u64 uid_gid;

  // make key
  key.inode = BPF_CORE_READ(dentry, d_inode, i_ino);
  key.dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  // delete from policy table
  bpf_map_delete_elem(&policy_table, &key);

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
  event->parent_inode_number = BPF_CORE_READ(dir, i_ino);

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = DELETE;
  event->before_size = val->file_size;
  event->after_size = 0;

  // populate rest of the event structure

  event->inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);
  event->dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);
  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);

  // submit event to ring buffer
  bpf_ringbuf_submit(event, 0);

  return 0;
}

//------------------------------- MODIFY ------------------------------------

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit_hook, struct file *file, const char *buf,
             size_t count, loff_t *pos, ssize_t ret) {

  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  __u64 uid_gid;

  // if no bytes are written then return early
  if (ret <= 0) {
    return 0;
  }

  /* Check the inode that is being written */
  key.inode = BPF_CORE_READ(file, f_inode, i_ino);
  key.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->parent_dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);
  event->parent_inode_number =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = MODIFY;
  event->change_type |= ret << 4;
  event->before_size = val->file_size;
  event->after_size = BPF_CORE_READ(file, f_inode, i_size);
  val->file_size = event->after_size;

  // update map for new size
  bpf_map_update_elem(&policy_table, &key, val, BPF_ANY);

  // populate rest of the event structure

  event->inode_number = key.inode;
  event->dev = key.dev;
  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);

  const unsigned char *name = BPF_CORE_READ(file->f_path.dentry, d_name.name);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);

  // submit event to ring buffer
  bpf_ringbuf_submit(event, 0);

  return 0;
}

// ----------------------------- Rename ---------------------------------

SEC("lsm/inode_rename")
int BPF_PROG(watchd_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry) {

  return 0;
}
