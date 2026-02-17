
#include "mtypes.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define DEBUG
#include "events.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

//----------------------------------- CREATE ---------------------------------
SEC("lsm/inode_init_security")
int BPF_PROG(inode_init_security_hook, struct inode *inode, struct inode *dir,
             const struct qstr *qstr, struct xattr *xattrs, int *xattr_count) {

  struct KEY key = {};
  struct EVENT *transaction;
  struct task_struct *task;
  __u32 *val;
  umode_t mode;

  /* Check the parent Inode  for key */
  key.inode_number = BPF_CORE_READ(dir, i_ino);
  key.dev_id = BPF_CORE_READ(dir, i_sb, s_dev);

  // Lookup for key in table
  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

  transaction = bpf_ringbuf_reserve(&events, sizeof(*transaction), 0);
  if (!transaction) {
    bpf_printk("Failed to reserve ring buffer space\n");
    return 0;
  }

  /* populate event structure */
  transaction->parent_inode_number = key.inode_number;
  transaction->parent_dev = key.dev_id;

  task = (struct task_struct *)bpf_get_current_task();
  get_tty_info(task, transaction);

  transaction->change_type = CREATE;
  transaction->mtime = BPF_CORE_READ(inode, i_ctime_sec);

  // check if newly created inode is directory or file
  mode = BPF_CORE_READ(inode, i_mode);
  if (S_ISDIR(mode)) {
    transaction->file_size = DIR_SIZE;
    transaction->after_size = DIR_SIZE;
  } else {
    transaction->file_size = 0;
    transaction->after_size = 0;
  }

  transaction->before_size = 0;

  // populate rest of the event structure
  populate_transaction(inode, transaction);
  bpf_probe_read_str(transaction->filename, sizeof(transaction->filename),
                     qstr->name);

  // submit event to ring buffer
  bpf_ringbuf_submit(transaction, 0);

  return 0;
}

//------------------------------------ DELETE ---------------------------------

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink_hook, const struct path *dir, struct dentry *dentry) {

  struct KEY key = {};
  struct EVENT *transaction;
  struct task_struct *task;
  struct inode *inode;
  __u32 *val;

  /* Check the inode that is being removed */
  key.inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);
  key.dev_id = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

#ifdef DEBUG
  bpf_printk("hit inode_unlink \n");
  bpf_printk("key ( %llu, %llu )\n", key.inode_number, key.dev_id);
#endif

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

#ifdef DEBUG
  bpf_printk("A file is deleted in restricted folders \n");
#endif

  task = (struct task_struct *)bpf_get_current_task();
  inode = BPF_CORE_READ(dentry, d_inode);
  transaction = bpf_ringbuf_reserve(&events, sizeof(*transaction), 0);
  if (!transaction) {
    bpf_printk("Failed to reserve ring buffer space\n");
    return 0;
  }
  /* populate event structure */
  transaction->parent_inode_number = key.inode_number;
  transaction->parent_dev = key.dev_id;
  get_tty_info(task, transaction);

  transaction->change_type = DELETE;
  transaction->mtime = BPF_CORE_READ(inode, i_atime_sec);
  transaction->after_size = 0;
  transaction->file_size = 0;
  transaction->before_size = BPF_CORE_READ(inode, i_size);

  populate_transaction(inode, transaction);
  bpf_probe_read_str(transaction->filename, sizeof(transaction->filename),
                     dentry->d_name.name);

  bpf_ringbuf_submit(transaction, 0);

  return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir_hook, const struct path *dir, struct dentry *dentry) {

  struct KEY key = {};
  struct EVENT *transaction;
  struct task_struct *task;
  struct inode *inode;
  __u32 *val;

  /* Check the inode that is being removed */
  key.inode_number = BPF_CORE_READ(dentry, d_inode, i_ino);
  key.dev_id = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

#ifdef DEBUG
  bpf_printk("hit path_rmdir \n");
  bpf_printk("key ( %llu, %llu )\n", key.inode_number, key.dev_id);
#endif

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

#ifdef DEBUG
  bpf_printk("A directory is deleted in restricted folders \n");
#endif

  task = (struct task_struct *)bpf_get_current_task();
  inode = BPF_CORE_READ(dentry, d_inode);
  transaction = bpf_ringbuf_reserve(&events, sizeof(*transaction), 0);
  if (!transaction) {
    bpf_printk("Failed to reserve ring buffer space\n");
    return 0;
  }
  /* populate event structure */
  transaction->parent_inode_number = key.inode_number;
  transaction->parent_dev = key.dev_id;
  get_tty_info(task, transaction);

  transaction->change_type = DELETE;
  transaction->mtime = BPF_CORE_READ(inode, i_atime_sec);
  transaction->after_size = 0;
  transaction->file_size = 0;
  transaction->before_size = BPF_CORE_READ(inode, i_size);

  populate_transaction(inode, transaction);
  bpf_probe_read_str(transaction->filename, sizeof(transaction->filename),
                     dentry->d_name.name);

  bpf_ringbuf_submit(transaction, 0);

  return 0;
}

//------------------------------- MODIFY ------------------------------------

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write_entry_hook, struct file *file, const char *buf,
             size_t count, loff_t *pos) {

  struct inode *inode;
  struct KEY key = {};
  __u64 *val;
  __u64 pid_tgid;
  __u64 before_size;

  /* Check the inode that is being written */
  key.inode_number = BPF_CORE_READ(file, f_inode, i_ino);
  key.dev_id = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  // #ifdef DEBUG
  //   bpf_printk("hit vfs_write_entry_hook \n");
  // #endif

  val = bpf_map_lookup_elem(&policy_table, &key);
  if (!val)
    return 0;

#ifdef DEBUG
  bpf_printk("A file will be written in restricted folders \n");
#endif
  pid_tgid = bpf_get_current_pid_tgid();
  before_size = BPF_CORE_READ(file, f_inode, i_size);
  bpf_map_update_elem(&file_size_map, &pid_tgid, &before_size, BPF_ANY);

  return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_hook, struct file *file, const char *buf, size_t count,
             loff_t *pos, ssize_t ret) {

  struct EVENT *transaction;
  struct task_struct *task;
  struct inode *inode;
  struct inode *parent_inode;
  struct dentry *dentry;
  struct dentry *parent_dentry;
  __u32 *val;
  __u64 pid_tgid;
  __s64 *before_size;

  pid_tgid = bpf_get_current_pid_tgid();

  before_size = bpf_map_lookup_elem(&file_size_map, &pid_tgid);

  // #ifdef DEBUG
  //   bpf_printk("hit vfs_write_hook \n");
  // #endif

  if (!before_size)
    return 0;

  bpf_map_delete_elem(&file_size_map, &pid_tgid);

#ifdef DEBUG
  bpf_printk("A directory is deleted in restricted folders \n");
#endif

  task = (struct task_struct *)bpf_get_current_task();
  inode = BPF_CORE_READ(file, f_inode);
  dentry = BPF_CORE_READ(file, f_path.dentry);

  transaction = bpf_ringbuf_reserve(&events, sizeof(*transaction), 0);
  if (!transaction) {
    bpf_printk("Failed to reserve ring buffer space\n");
    return 0;
  }
  /* populate event structure */
  transaction->parent_inode_number = 0;
  transaction->parent_dev = 0;

  /* Get parent dentry and inode */
  parent_dentry = BPF_CORE_READ(dentry, d_parent);
  if (parent_dentry) {
    parent_inode = BPF_CORE_READ(parent_dentry, d_inode);
    if (parent_inode) {
      transaction->parent_inode_number = BPF_CORE_READ(parent_inode, i_ino);
      transaction->parent_dev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
    }
  }

  get_tty_info(task, transaction);

  transaction->change_type = MODIFY;
  transaction->mtime = BPF_CORE_READ(inode, i_mtime_sec);
  transaction->after_size = BPF_CORE_READ(file, f_inode, i_size);
  transaction->file_size = *before_size;
  transaction->before_size = *before_size;

  populate_transaction(inode, transaction);
  bpf_probe_read_str(transaction->filename, sizeof(transaction->filename),
                     file->f_path.dentry->d_name.name);

  bpf_ringbuf_submit(transaction, 0);

  return 0;
}
