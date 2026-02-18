#ifndef MTYPES_H
#define MTYPES_H

#include "vmlinux.h"

#define NAME_MAX 255
#define CREATE 0x1
#define MODIFY 0x2
#define DELETE 0x3

#ifndef S_IFMT
#define S_IFMT 0170000
#endif

#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

struct EVENT {

  // parent Inode number and dev
  __u64 parent_inode_number;
  __u64 parent_dev;

  // for map key in userspace
  __u64 inode_number;
  __u64 dev;

  // for username in userspace
  __u32 uid;
  __u32 change_type; // [31:4] bytes written ,[3:0] event type

  // tty
  __u32 tty_index;
  __s32 tty_major;

  // file size
  __s64 before_size;
  __s64 after_size;

  // filename
  char filename[NAME_MAX];
};

struct KEY {
  __u64 inode;
  __u64 dev;
};

struct VALUE {
  __s64 file_size;
};

#endif