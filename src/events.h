#ifndef EVENTS_H
#define EVENTS_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "mtypes.h"

static int populate_transaction(struct inode *inode,
                                struct EVENT *transaction) {

  __u64 uid_gid;
  transaction->inode_number = (__u32)BPF_CORE_READ(inode, i_ino);
  transaction->dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
  uid_gid = bpf_get_current_uid_gid();
  transaction->uid = (__u32)(uid_gid & 0xffffffff);
  transaction->gid = (__u32)(uid_gid >> 32);
  transaction->mtime = BPF_CORE_READ(inode, i_ctime_sec);
  // transaction->change_type = CREATE;

#ifdef DEBUG
  bpf_printk("mtime value: %llu", transaction->mtime);
  bpf_printk("chnage type value: %d", transaction->change_type);
#endif

  // transaction->after_size = 0;
  // transaction->before_size = 0;
  // transaction->file_size = 0;

  return 0;
}

static void get_tty_info(struct task_struct *task, struct EVENT *transaction) {
  struct signal_struct *signal;
  struct tty_struct *tty;
  struct tty_driver *driver;

  /* Initialize output */
  transaction->tty_index = -1;
  if (!task) {
#ifdef DEBUG
    bpf_printk("get_tty_info: task is NULL\n");
#endif
    return;
  }

  signal = BPF_CORE_READ(task, signal);
  if (!signal) {
#ifdef DEBUG
    bpf_printk("get_tty_info: task has no signal (kthread)\n");
#endif
    return;
  }

  tty = BPF_CORE_READ(signal, tty);
  if (!tty) {
#ifdef DEBUG
    bpf_printk("get_tty_info: no tty attached\n");
#endif
    return;
  }
  transaction->tty_index = (__u32)BPF_CORE_READ(tty, index);
  driver = BPF_CORE_READ(tty, driver);
  if (!driver) {
#ifdef DEBUG
    bpf_printk("get_tty_info: tty has no driver\n");
#endif
    return;
  }

  transaction->tty_major = (__u32)BPF_CORE_READ(driver, major);

#ifdef DEBUG
  bpf_printk("get_tty_info: tty major=%d index=%d\n", transaction->tty_major,
             transaction->tty_index);
#endif
}

#endif