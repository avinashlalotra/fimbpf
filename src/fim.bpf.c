
#include "maps.h"
#include "mtypes.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

//----------------------------------- CREATE ---------------------------------
SEC("lsm/d_instantiate")
int BPF_PROG(watchd_d_instantiate, struct dentry *dentry, struct inode *inode) {

  struct KEY key = {};
  struct EVENT *event;
  struct task_struct *task;
  struct VALUE *val;
  umode_t mode;
  __u64 uid_gid;

  // make key
  key.inode = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);
  key.dev = BPF_CORE_READ(dentry, d_parent, d_inode, i_sb, s_dev);

  val = bpf_map_lookup_elem(&policy_table, &key);

  if (!val)
    return 0;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->parent_dev = key.dev;
  event->parent_inode_number = key.inode;

  task = (struct task_struct *)bpf_get_current_task();
  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_index = BPF_CORE_READ(task, signal, tty, index);

  event->change_type = CREATE;

  mode = BPF_CORE_READ(inode, i_mode);
  if (S_ISDIR(mode)) {
    event->after_size = DIR_SIZE;
  } else {
    event->after_size = 0;
  }

  event->before_size = 0;

  // populate rest of the event structure

  event->inode_number = (__u32)BPF_CORE_READ(inode, i_ino);
  event->dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
  uid_gid = bpf_get_current_uid_gid();
  event->uid = (__u32)(uid_gid & 0xffffffff);
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                            dentry->d_name.name);

  // submit event to ring buffer
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
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                            dentry->d_name.name);

  // submit event to ring buffer
  bpf_ringbuf_submit(event, 0);

  return 0;
}

// //------------------------------- MODIFY ------------------------------------

// SEC("fentry/vfs_write")
// int BPF_PROG(vfs_write_entry_hook, struct file *file, const char *buf,
//              size_t count, loff_t *pos) {

//   struct inode *inode;
//   struct KEY key = {};
//   __u64 *val;
//   __u64 pid_tgid;
//   __u64 before_size;

//   /* Check the inode that is being written */
//   key.inode_number = BPF_CORE_READ(file, f_inode, i_ino);
//   key.dev_id = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

//   // #ifdef DEBUG
//   //   bpf_printk("hit vfs_write_entry_hook \n");
//   // #endif

//   val = bpf_map_lookup_elem(&policy_table, &key);
//   if (!val)
//     return 0;

// #ifdef DEBUG
//   bpf_printk("A file will be written in restricted folders \n");
// #endif
//   pid_tgid = bpf_get_current_pid_tgid();
//   before_size = BPF_CORE_READ(file, f_inode, i_size);
//   bpf_map_update_elem(&file_size_map, &pid_tgid, &before_size, BPF_ANY);

//   return 0;
// }

// SEC("fexit/vfs_write")
// int BPF_PROG(vfs_write_hook, struct file *file, const char *buf, size_t
// count,
//              loff_t *pos, ssize_t ret) {

//   struct EVENT *transaction;
//   struct task_struct *task;
//   struct inode *inode;
//   struct inode *parent_inode;
//   struct dentry *dentry;
//   struct dentry *parent_dentry;
//   __u32 *val;
//   __u64 pid_tgid;
//   __s64 *before_size;

//   pid_tgid = bpf_get_current_pid_tgid();

//   before_size = bpf_map_lookup_elem(&file_size_map, &pid_tgid);

//   // #ifdef DEBUG
//   //   bpf_printk("hit vfs_write_hook \n");
//   // #endif

//   if (!before_size)
//     return 0;

//   bpf_map_delete_elem(&file_size_map, &pid_tgid);

// #ifdef DEBUG
//   bpf_printk("A directory is deleted in restricted folders \n");
// #endif

//   task = (struct task_struct *)bpf_get_current_task();
//   inode = BPF_CORE_READ(file, f_inode);
//   dentry = BPF_CORE_READ(file, f_path.dentry);

//   transaction = bpf_ringbuf_reserve(&events, sizeof(*transaction), 0);
//   if (!transaction) {
//     bpf_printk("Failed to reserve ring buffer space\n");
//     return 0;
//   }
//   /* populate event structure */
//   transaction->parent_inode_number = 0;
//   transaction->parent_dev = 0;

//   /* Get parent dentry and inode */
//   parent_dentry = BPF_CORE_READ(dentry, d_parent);
//   if (parent_dentry) {
//     parent_inode = BPF_CORE_READ(parent_dentry, d_inode);
//     if (parent_inode) {
//       transaction->parent_inode_number = BPF_CORE_READ(parent_inode, i_ino);
//       transaction->parent_dev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
//     }
//   }

//   transaction->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
//   transaction->tty_index = BPF_CORE_READ(task, signal, tty, index);

//   transaction->change_type = MODIFY;
//   transaction->file_size = *before_size;

//   transaction->inode_number = (__u64)BPF_CORE_READ(inode, i_ino);
//   transaction->dev = (__u64)BPF_CORE_READ(inode, i_sb, s_dev);
//   uid_gid = bpf_get_current_uid_gid();
//   transaction->uid = (__u32)(uid_gid & 0xffffffff);
//   transaction->gid = (__u32)(uid_gid >> 32);
//   bpf_probe_read_str(transaction->filename, sizeof(transaction->filename),
//                      file->f_path.dentry->d_name.name);

//   bpf_ringbuf_submit(transaction, 0);

//   return 0;
// }
