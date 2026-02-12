#ifndef MTYPES_H
#define MTYPES_H

#include "vmlinux.h"

#define NAME_MAX 255
#define CREATE 1
#define MODIFY 2
#define DELETE 3

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
  __u32 gid;

  // last modified time and chnage type
  __u64 change_type;
  time64_t mtime;

  // tty
  __u32 tty_index;
  __s32 tty_major;

  // file size
  __s64 file_size;
  __s64 before_size;
  __s64 after_size;

  // filename
  char filename[NAME_MAX];
};

struct KEY {
  __u64 inode_number;
  __u64 dev_id;
};

struct VALUE {
  __u8 value;
};

#endif