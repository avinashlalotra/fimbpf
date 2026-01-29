#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vfs_monitor.bpf.h"


SEC("fexit/vfs_create")
int BPF_PROG(vfs_create_hook,
    struct mnt_idmap *mnt_idmap,
    struct inode *inode,
    struct dentry *dentry,
    umode_t mode,
    bool want_excl,
    int ret
)
{
    return 0;
}


SEC("fentry/vfs_mkdir")
int BPF_PROG(vfs_mkdir_hook,
    struct mnt_idmap *mnt_idmap,
    struct inode *inode,
    struct dentry *dentry,
    umode_t mode
)
{
    return 0;
}


SEC("fexit/vfs_mknod")
int BPF_PROG(vfs_mknod_hook,
    struct mnt_idmap *mnt_idmap,
    struct inode *inode,
    struct dentry *dentry,
    umode_t mode,
    dev_t dev,
    int ret
)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
