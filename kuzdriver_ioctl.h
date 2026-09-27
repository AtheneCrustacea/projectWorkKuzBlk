#ifndef _MYBLOCK_IOCTL_H
#define _MYBLOCK_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define MYBLOCK_IOCTL_MAGIC 'K'

// 256-bit symmetric key
struct myblock_key {
  __u8 key[32];
};

struct myblock_status {
  __u8 locked;  // 0 = locked, 1 = unlocked
  __u8 key_set; // 0 = key is set, 1 = key not set
  __u8 crypto_enabled;
  __u8 reserved[5];
  __u64 reads;         // read ops count
  __u64 writes;        // write ops count
  __u64 bytes_read;    // bytes read
  __u64 bytes_written; // bytes written
};

#define MYBLOCK_IOCTL_SET_KEY _IOW(MYBLOCK_IOCTL_MAGIC, 1, struct myblock_key)
#define MYBLOCK_IOCTL_LOCK _IO(MYBLOCK_IOCTL_MAGIC, 2)
#define MYBLOCK_IOCTL_UNLOCK _IO(MYBLOCK_IOCTL_MAGIC, 3)
#define MYBLOCK_IOCTL_GET_STATUS                                               \
  _IOR(MYBLOCK_IOCTL_MAGIC, 4, struct myblock_status)
#define MYBLOCK_IOCTL_ENABLE_CRYPTO _IO(MYBLOCK_IOCTL_MAGIC, 5)
#define MYBLOCK_IOCTL_DISABLE_CRYPTO _IO(MYBLOCK_IOCTL_MAGIC, 6)

#endif /* _MYBLOCK_IOCTL_H */