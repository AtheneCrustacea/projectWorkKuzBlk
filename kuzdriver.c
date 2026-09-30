#include <crypto/skcipher.h>
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "kuzdriver_ioctl.h"

#define DRIVER_NAME "KuzDriver"
#define DEVICE_NAME "KuzEncDev"

#define NUM_PARTITIONS 3
#define PARTITION_SIZE_MB 100
#define PARTITION_SIZE_BYTES (PARTITION_SIZE_MB * 1024ULL * 1024ULL)
#define PARTITION_SIZE_SECT (PARTITION_SIZE_BYTES / 512)

#define FIRST_PART_SECT 2048

// whole disk size
#define WHOLE_DISK_SECT (FIRST_PART_SECT + NUM_PARTITIONS * PARTITION_SIZE_SECT)

#define KUZ_IV_SIZE 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("H8SM");
MODULE_DESCRIPTION(
    "Block device driver with transparent Kuznyechik CTR encryption");
MODULE_VERSION("1.0");

struct myblock_device;

struct kuz_partition {
  int index;           // 1..3
  char name[32];       // KuzEncDev1
  sector_t start_sect; // relative to whole disk
  sector_t nr_sects;

  struct mutex key_lock;
  u8 key[32];
  bool key_set;
  atomic_t locked;
  atomic_t crypto_enabled;
  atomic64_t reads, writes, bytes_read, bytes_written;

  struct crypto_skcipher *tfm;
  struct kobject kobj; // /sys/class/kuzdriver/KuzEncDev/<name>
  bool sysfs_ready;
};

struct myblock_device {
  struct gendisk *gd;
  u8 *data;
  int major;
  struct kuz_partition parts[NUM_PARTITIONS];
  struct device *sysfs_dev; // /sys/class/kuzdriver/KuzEncDev
  bool disk_added;
};

static struct myblock_device *mydev;
static struct class *kuzdriver_class;

// block_device_operations

static int myblock_open(struct gendisk *disk, blk_mode_t mode) {
  pr_info(DRIVER_NAME ": %s opened\n", disk->disk_name);
  return 0;
}

static void myblock_release(struct gendisk *disk) {
  pr_info(DRIVER_NAME ": %s closed\n", disk->disk_name);
}

// helpers

static struct kuz_partition *
find_partition_by_sector(struct myblock_device *dev, sector_t sector) {
  int i;
  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct kuz_partition *p = &dev->parts[i];
    if (sector >= p->start_sect && sector < p->start_sect + p->nr_sects)
      return p;
  }
  return NULL;
}

static struct scatterlist *myblock_sg_from_vmalloc(void *buf, size_t len,
                                                   int *nents_out) {
  struct scatterlist *sg;
  unsigned long addr = (unsigned long)buf;
  unsigned long offset = offset_in_page(addr);
  size_t remaining = len;
  int nents = DIV_ROUND_UP(offset + len, PAGE_SIZE);
  int i;

  sg = kmalloc_array(nents, sizeof(*sg), GFP_KERNEL);
  if (!sg)
    return NULL;
  sg_init_table(sg, nents);

  for (i = 0; i < nents; i++) {
    struct page *page = vmalloc_to_page((void *)addr);
    size_t seg_len = min_t(size_t, PAGE_SIZE - offset, remaining);

    if (!page) {
      kfree(sg);
      return NULL;
    }
    sg_set_page(&sg[i], page, seg_len, offset);
    addr += seg_len;
    remaining -= seg_len;
    offset = 0;
  }
  *nents_out = nents;
  return sg;
}

// encryption itself
static int myblock_crypt_data(struct kuz_partition *part, u64 sector, void *buf,
                              size_t len, bool encrypt) {
  struct scatterlist *sg;
  struct skcipher_request *req;
  u8 iv[KUZ_IV_SIZE] = {0};
  int nents, ret;

  sg = myblock_sg_from_vmalloc(buf, len, &nents);
  if (!sg)
    return -ENOMEM;

  req = skcipher_request_alloc(part->tfm, GFP_KERNEL);
  if (!req) {
    kfree(sg);
    return -ENOMEM;
  }

  *(__le64 *)iv = cpu_to_le64(sector);
  skcipher_request_set_crypt(req, sg, sg, len, iv);

  if (encrypt)
    ret = crypto_skcipher_encrypt(req);
  else
    ret = crypto_skcipher_decrypt(req);

  skcipher_request_free(req);
  kfree(sg);
  return ret;
}

// submit_bio

static void myblock_submit_bio(struct bio *bio) {
  struct myblock_device *dev = bio->bi_bdev->bd_disk->private_data;
  struct bvec_iter iter;
  struct bio_vec bvec;
  bool is_write = (bio_op(bio) == REQ_OP_WRITE);

  bio_for_each_segment(bvec, bio, iter) {
    void *iovec_mem;
    unsigned int len = bvec.bv_len;
    sector_t abs_sector = iter.bi_sector;
    unsigned int dev_offset;
    struct kuz_partition *part;
    bool do_crypt;
    int ret;

    if (abs_sector + (len >> 9) >
        WHOLE_DISK_SECT) { // ">> 9" equal to "divide by 512"
      bio_io_error(bio);
      return;
    }

    dev_offset = abs_sector * 512;
    part = find_partition_by_sector(dev, abs_sector);

    if (part && atomic_read(&part->locked)) {
      pr_info(DRIVER_NAME ": %s locked, I/O denied\n", part->name);
      bio_io_error(bio);
      return;
    }

    do_crypt = part && part->key_set && atomic_read(&part->crypto_enabled);

    if (is_write) {
      iovec_mem = kmap_local_page(bvec.bv_page);
      if (!iovec_mem) {
        bio_io_error(bio);
        return;
      }
      iovec_mem += bvec.bv_offset;
      memcpy(dev->data + dev_offset, iovec_mem, len);
      kunmap_local(iovec_mem - bvec.bv_offset);

      if (do_crypt) {
        ret = myblock_crypt_data(part, abs_sector, dev->data + dev_offset, len,
                                 true);
        if (ret) {
          bio_io_error(bio);
          return;
        }
      }
    } else {
      if (do_crypt) {
        ret = myblock_crypt_data(part, abs_sector, dev->data + dev_offset, len,
                                 false);
        if (ret) {
          bio_io_error(bio);
          return;
        }
      }

      iovec_mem = kmap_local_page(bvec.bv_page);
      if (!iovec_mem) {
        bio_io_error(bio);
        return;
      }
      iovec_mem += bvec.bv_offset;
      memcpy(iovec_mem, dev->data + dev_offset, len);
      kunmap_local(iovec_mem - bvec.bv_offset);
    }

    if (part) {
      if (is_write) {
        atomic64_inc(&part->writes);
        atomic64_add(len, &part->bytes_written);
      } else {
        atomic64_inc(&part->reads);
        atomic64_add(len, &part->bytes_read);
      }
    }
  }

  bio_endio(bio);
}

// ioctl

static int myblock_ioctl(struct block_device *bdev, blk_mode_t mode,
                         unsigned int cmd, unsigned long arg) {
  struct myblock_device *dev = bdev->bd_disk->private_data;
  sector_t bdev_start = get_start_sect(bdev);
  struct kuz_partition *part = NULL;
  void __user *argp = (void __user *)arg;
  int i;

  if (bdev_start != 0) {
    for (i = 0; i < NUM_PARTITIONS; i++) {
      if (dev->parts[i].start_sect == bdev_start) {
        part = &dev->parts[i];
        break;
      }
    }
    if (!part)
      return -ENODEV;
  }

  switch (cmd) {
  case MYBLOCK_IOCTL_SET_KEY: {
    struct myblock_key k;
    int ret;

    if (copy_from_user(&k, argp, sizeof(k)))
      return -EFAULT;

    if (part) {
      mutex_lock(&part->key_lock);
      ret = crypto_skcipher_setkey(part->tfm, k.key, 32);
      if (!ret) {
        memcpy(part->key, k.key, 32);
        part->key_set = true;
      }
      mutex_unlock(&part->key_lock);
      return ret;
    }

    // set key for all partitions
    for (i = 0; i < NUM_PARTITIONS; i++) {
      struct kuz_partition *p = &dev->parts[i];
      mutex_lock(&p->key_lock);
      ret = crypto_skcipher_setkey(p->tfm, k.key, 32);
      if (!ret) {
        memcpy(p->key, k.key, 32);
        p->key_set = true;
      }
      mutex_unlock(&p->key_lock);
      if (ret)
        return ret;
    }
    return 0;
  }

  case MYBLOCK_IOCTL_LOCK:
    if (part) {
      atomic_set(&part->locked, 1);
    } else {
      for (i = 0; i < NUM_PARTITIONS; i++)
        atomic_set(&dev->parts[i].locked, 1);
    }
    return 0;

  case MYBLOCK_IOCTL_UNLOCK:
    if (part) {
      atomic_set(&part->locked, 0);
    } else {
      for (i = 0; i < NUM_PARTITIONS; i++)
        atomic_set(&dev->parts[i].locked, 0);
    }
    return 0;

  case MYBLOCK_IOCTL_ENABLE_CRYPTO:
    if (part) {
      atomic_set(&part->crypto_enabled, 1);
    } else {
      for (i = 0; i < NUM_PARTITIONS; i++)
        atomic_set(&dev->parts[i].crypto_enabled, 1);
    }
    return 0;

  case MYBLOCK_IOCTL_DISABLE_CRYPTO:
    if (part) {
      atomic_set(&part->crypto_enabled, 0);
    } else {
      for (i = 0; i < NUM_PARTITIONS; i++)
        atomic_set(&dev->parts[i].crypto_enabled, 0);
    }
    return 0;

  case MYBLOCK_IOCTL_GET_STATUS: {
    struct myblock_status st;

    memset(&st, 0, sizeof(st));
    if (part) {
      mutex_lock(&part->key_lock);
      st.key_set = part->key_set ? 1 : 0;
      mutex_unlock(&part->key_lock);
      st.locked = atomic_read(&part->locked) ? 1 : 0;
      st.crypto_enabled = atomic_read(&part->crypto_enabled) ? 1 : 0;
      st.reads = atomic64_read(&part->reads);
      st.writes = atomic64_read(&part->writes);
      st.bytes_read = atomic64_read(&part->bytes_read);
      st.bytes_written = atomic64_read(&part->bytes_written);
    } else {
      bool all_locked = true;
      u64 reads = 0, writes = 0, br = 0, bw = 0;
      for (i = 0; i < NUM_PARTITIONS; i++) {
        reads += atomic64_read(&dev->parts[i].reads);
        writes += atomic64_read(&dev->parts[i].writes);
        br += atomic64_read(&dev->parts[i].bytes_read);
        bw += atomic64_read(&dev->parts[i].bytes_written);
        if (!atomic_read(&dev->parts[i].locked)) {
          all_locked = false;
        }
      }
      st.locked = all_locked ? 1 : 0;
      st.reads = reads;
      st.writes = writes;
      st.bytes_read = br;
      st.bytes_written = bw;
    }

    if (copy_to_user(argp, &st, sizeof(st)))
      return -EFAULT;
    return 0;
  }

  default:
    return -ENOTTY;
  }
}

static const struct block_device_operations myblock_fops = {
    .owner = THIS_MODULE,
    .open = myblock_open,
    .release = myblock_release,
    .submit_bio = myblock_submit_bio,
    .ioctl = myblock_ioctl,
};

// MBR

static void build_mbr(u8 *sector) {
  struct mbr_entry {
    u8 status;
    u8 chs_start[3];
    u8 type;
    u8 chs_end[3];
    __le32 lba_start;
    __le32 nr_sectors;
  } __packed;
  struct mbr_entry *p;
  sector_t start = FIRST_PART_SECT;
  int i;

  memset(sector, 0, 512);
  p = (struct mbr_entry *)(sector + 446);
  for (i = 0; i < NUM_PARTITIONS; i++) {
    p[i].status = 0;
    p[i].chs_start[0] = 0xFE;
    p[i].chs_start[1] = 0xFF;
    p[i].chs_start[2] = 0xFF;
    p[i].type = 0x83;
    p[i].chs_end[0] = 0xFE;
    p[i].chs_end[1] = 0xFF;
    p[i].chs_end[2] = 0xFF;
    p[i].lba_start = cpu_to_le32(start);
    p[i].nr_sectors = cpu_to_le32(PARTITION_SIZE_SECT);
    start += PARTITION_SIZE_SECT;
  }
  sector[510] = 0x55;
  sector[511] = 0xAA;
}

// sysfs stuff

static ssize_t disk_size_show(struct device *d, struct device_attribute *a,
                              char *b) {
  return sysfs_emit(b, "%llu\n", (unsigned long long)WHOLE_DISK_SECT * 512);
}

static ssize_t disk_locked_show(struct device *d, struct device_attribute *a,
                                char *b) {
  struct myblock_device *dev = dev_get_drvdata(d);
  int i;
  for (i = 0; i < NUM_PARTITIONS; i++)
    if (!atomic_read(&dev->parts[i].locked))
      return sysfs_emit(b, "0\n");
  return sysfs_emit(b, "1\n");
}

static ssize_t disk_locked_store(struct device *d, struct device_attribute *a,
                                 const char *buf, size_t count) {
  struct myblock_device *dev = dev_get_drvdata(d);
  unsigned long val;
  int i;

  if (kstrtoul(buf, 10, &val))
    return -EINVAL;
  for (i = 0; i < NUM_PARTITIONS; i++)
    atomic_set(&dev->parts[i].locked, val ? 1 : 0);
  return count;
}

static struct device_attribute dev_attr_size_w =
    __ATTR(size, 0444, disk_size_show, NULL);
static struct device_attribute dev_attr_locked_w =
    __ATTR(locked, 0644, disk_locked_show, disk_locked_store);

static struct attribute *disk_attrs[] = {
    &dev_attr_size_w.attr,
    &dev_attr_locked_w.attr,
    NULL,
};

static const struct attribute_group disk_attr_group = {
    .attrs = disk_attrs,
};

static const struct attribute_group *disk_attr_groups[] = {
    &disk_attr_group,
    NULL,
};

// sysfs: partition kobjects

static ssize_t part_attr_show(struct kobject *kobj, struct attribute *attr,
                              char *buf) {
  struct kuz_partition *part = container_of(kobj, struct kuz_partition, kobj);
  const char *name = attr->name;

  if (!strcmp(name, "size"))
    return sysfs_emit(buf, "%llu\n", (unsigned long long)part->nr_sects * 512);
  if (!strcmp(name, "start"))
    return sysfs_emit(buf, "%llu\n", (unsigned long long)part->start_sect);
  if (!strcmp(name, "locked"))
    return sysfs_emit(buf, "%d\n", atomic_read(&part->locked) ? 1 : 0);
  if (!strcmp(name, "key_set")) {
    int v;
    mutex_lock(&part->key_lock);
    v = part->key_set;
    mutex_unlock(&part->key_lock);
    return sysfs_emit(buf, "%d\n", v);
  }
  if (!strcmp(name, "crypto_enabled"))
    return sysfs_emit(buf, "%d\n", atomic_read(&part->crypto_enabled) ? 1 : 0);
  if (!strcmp(name, "reads"))
    return sysfs_emit(buf, "%llu\n",
                      (unsigned long long)atomic64_read(&part->reads));
  if (!strcmp(name, "writes"))
    return sysfs_emit(buf, "%llu\n",
                      (unsigned long long)atomic64_read(&part->writes));
  if (!strcmp(name, "bytes_read"))
    return sysfs_emit(buf, "%llu\n",
                      (unsigned long long)atomic64_read(&part->bytes_read));
  if (!strcmp(name, "bytes_written"))
    return sysfs_emit(buf, "%llu\n",
                      (unsigned long long)atomic64_read(&part->bytes_written));
  return -EIO;
}

static ssize_t part_attr_store(struct kobject *kobj, struct attribute *attr,
                               const char *buf, size_t count) {
  struct kuz_partition *part = container_of(kobj, struct kuz_partition, kobj);
  const char *name = attr->name;
  unsigned long val;

  if (kstrtoul(buf, 10, &val))
    return -EINVAL;

  if (!strcmp(name, "locked")) {
    atomic_set(&part->locked, val ? 1 : 0);
    return count;
  }
  if (!strcmp(name, "crypto_enabled")) {
    atomic_set(&part->crypto_enabled, val ? 1 : 0);
    return count;
  }
  return -EIO;
}

static const struct sysfs_ops part_sysfs_ops = {
    .show = part_attr_show,
    .store = part_attr_store,
};

static void part_kobj_release(struct kobject *kobj) { return; }

static struct kobj_type part_ktype = {
    .sysfs_ops = &part_sysfs_ops,
    .release = part_kobj_release,
};

static struct attribute part_attr_size = {.name = "size", .mode = 0444};
static struct attribute part_attr_start = {.name = "start", .mode = 0444};
static struct attribute part_attr_locked = {.name = "locked", .mode = 0644};
static struct attribute part_attr_keyset = {.name = "key_set", .mode = 0444};
static struct attribute part_attr_crypto = {.name = "crypto_enabled",
                                            .mode = 0644};
static struct attribute part_attr_reads = {.name = "reads", .mode = 0444};
static struct attribute part_attr_writes = {.name = "writes", .mode = 0444};
static struct attribute part_attr_br = {.name = "bytes_read", .mode = 0444};
static struct attribute part_attr_bw = {.name = "bytes_written", .mode = 0444};

static struct attribute *part_attrs[] = {
    &part_attr_size,   &part_attr_start,
    &part_attr_locked, &part_attr_keyset,
    &part_attr_crypto, &part_attr_reads,
    &part_attr_writes, &part_attr_br,
    &part_attr_bw,     NULL,
};

static const struct attribute_group part_attr_group = {
    .attrs = part_attrs,
};

// proc

static int kuzdriver_proc_show(struct seq_file *m, void *v) {
  int i;

  seq_puts(m, "KuzDriver status (whole disk + partitions)\n");
  seq_puts(m, "=========================================\n\n");
  seq_printf(m, "Whole disk size:  %llu bytes\n",
             (unsigned long long)WHOLE_DISK_SECT * 512);
  {
    bool all_locked = true;
    for (i = 0; i < NUM_PARTITIONS; i++)
      if (!atomic_read(&mydev->parts[i].locked))
        all_locked = false;
    seq_printf(m, "Whole disk locked: %s\n\n", all_locked ? "yes" : "no");
  }

  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct kuz_partition *p = &mydev->parts[i];
    bool key_set;

    mutex_lock(&p->key_lock);
    key_set = p->key_set;
    mutex_unlock(&p->key_lock);

    seq_printf(m, "partition %d: /dev/%s\n", p->index, p->name);
    seq_printf(m, "  start_sect:     %llu\n",
               (unsigned long long)p->start_sect);
    seq_printf(m, "  size:           %u MiB\n", PARTITION_SIZE_MB);
    seq_printf(m, "  locked:         %s\n",
               atomic_read(&p->locked) ? "yes" : "no");
    seq_printf(m, "  key_set:        %s\n", key_set ? "yes" : "no");
    seq_printf(m, "  crypto_enabled: %s\n",
               atomic_read(&p->crypto_enabled) ? "yes" : "no");
    seq_printf(m, "  reads:          %llu\n",
               (unsigned long long)atomic64_read(&p->reads));
    seq_printf(m, "  writes:         %llu\n",
               (unsigned long long)atomic64_read(&p->writes));
    seq_printf(m, "  bytes_read:     %llu\n",
               (unsigned long long)atomic64_read(&p->bytes_read));
    seq_printf(m, "  bytes_written:  %llu\n",
               (unsigned long long)atomic64_read(&p->bytes_written));
    seq_puts(m, "\n");
  }
  return 0;
}

// freeing

static void myblock_free_device(void) {
  int i;

  if (!mydev)
    return;

  if (mydev->gd) {
    if (mydev->disk_added) {
      del_gendisk(mydev->gd);
    }
    put_disk(mydev->gd);
    mydev->gd = NULL;
    mydev->disk_added = false;
  }

  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct kuz_partition *p = &mydev->parts[i];
    if (p->tfm) {
      crypto_free_skcipher(p->tfm);
      p->tfm = NULL;
    }
    memzero_explicit(p->key, sizeof(p->key));
    mutex_destroy(&p->key_lock);
  }

  if (mydev->data) {
    vfree(mydev->data);
    mydev->data = NULL;
  }
}

// init + exit

static int __init myblock_init(void) {
  int ret;
  int i;

  pr_info(DRIVER_NAME ": loading\n");

  mydev = kzalloc(sizeof(*mydev), GFP_KERNEL);
  if (!mydev)
    return -ENOMEM;

  mydev->major = register_blkdev(0, DEVICE_NAME);
  if (mydev->major < 0) {
    ret = mydev->major;
    pr_err(DRIVER_NAME ": register_blkdev failed: %d\n", ret);
    kfree(mydev);
    mydev = NULL;
    return ret;
  }

  // partitions init
  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct kuz_partition *p = &mydev->parts[i];

    p->index = i + 1;
    snprintf(p->name, sizeof(p->name), "%s%d", DEVICE_NAME, i + 1);
    p->start_sect = FIRST_PART_SECT + i * PARTITION_SIZE_SECT;
    p->nr_sects = PARTITION_SIZE_SECT;

    mutex_init(&p->key_lock);
    p->key_set = false;
    atomic_set(&p->locked, 0);
    atomic_set(&p->crypto_enabled, 1);
    atomic64_set(&p->reads, 0);
    atomic64_set(&p->writes, 0);
    atomic64_set(&p->bytes_read, 0);
    atomic64_set(&p->bytes_written, 0);

    p->tfm = crypto_alloc_skcipher("ctr(kuznyechik)", 0, 0);
    if (IS_ERR(p->tfm)) {
      ret = PTR_ERR(p->tfm);
      p->tfm = NULL;
      pr_err(DRIVER_NAME ": crypto_alloc_skcipher failed: %d\n", ret);
      goto err_cleanup;
    }
  }

  // big block dev blob
  mydev->data = vmalloc(WHOLE_DISK_SECT * 512);
  if (!mydev->data) {
    ret = -ENOMEM;
    goto err_cleanup;
  }
  memset(mydev->data, 0, WHOLE_DISK_SECT * 512);

  // magic stuff that makes it 3 paritions and not 3 different devices
  build_mbr(mydev->data);

  {
    struct queue_limits lim = {
        .physical_block_size = PAGE_SIZE,
        .features = BLK_FEAT_SYNCHRONOUS,
    };

    mydev->gd = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if (IS_ERR(mydev->gd)) {
      ret = PTR_ERR(mydev->gd);
      mydev->gd = NULL;
      pr_err(DRIVER_NAME ": blk_alloc_disk failed: %d\n", ret);
      goto err_cleanup;
    }
  }

  mydev->gd->major = mydev->major;
  mydev->gd->first_minor = 0;
  mydev->gd->minors = NUM_PARTITIONS + 1;
  mydev->gd->fops = &myblock_fops;
  mydev->gd->private_data = mydev;

  snprintf(mydev->gd->disk_name, DISK_NAME_LEN, DEVICE_NAME);
  set_capacity(mydev->gd, WHOLE_DISK_SECT);

  ret = add_disk(mydev->gd);
  if (ret) {
    pr_err(DRIVER_NAME ": add_disk failed: %d\n", ret);
    mydev->gd->private_data = NULL;
    goto err_cleanup;
  }
  mydev->disk_added = true;

  // sysfs init
  kuzdriver_class = class_create("kuzdriver");
  if (IS_ERR(kuzdriver_class)) {
    ret = PTR_ERR(kuzdriver_class);
    kuzdriver_class = NULL;
    pr_err(DRIVER_NAME ": class_create failed: %d\n", ret);
    goto err_cleanup;
  }

  mydev->sysfs_dev = device_create_with_groups(kuzdriver_class, NULL, 0, mydev,
                                               disk_attr_groups, DEVICE_NAME);

  if (IS_ERR(mydev->sysfs_dev)) {
    ret = PTR_ERR(mydev->sysfs_dev);
    mydev->sysfs_dev = NULL;
    pr_err(DRIVER_NAME ": device_create failed: %d\n", ret);
    goto err_cleanup;
  }

  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct kuz_partition *p = &mydev->parts[i];

    kobject_init(&p->kobj, &part_ktype);
    ret = kobject_add(&p->kobj, &mydev->sysfs_dev->kobj, "%s", p->name);
    if (ret) {
      pr_err(DRIVER_NAME ": kobject_add failed: %d\n", ret);
      kobject_put(&p->kobj);
      goto err_cleanup;
    }
    ret = sysfs_create_group(&p->kobj, &part_attr_group);
    if (ret) {
      pr_err(DRIVER_NAME ": sysfs_create_group failed: %d\n", ret);
      kobject_del(&p->kobj);
      kobject_put(&p->kobj);
      goto err_cleanup;
    }
    p->sysfs_ready = true;
  }

  if (!proc_create_single("kuzdriver", 0444, NULL, kuzdriver_proc_show)) {
    ret = -ENOMEM;
    pr_err(DRIVER_NAME ": proc_create_single failed\n");
    goto err_cleanup;
  }

  pr_info(DRIVER_NAME ": all %d partitions registered\n", NUM_PARTITIONS);
  return 0;

err_cleanup:
  remove_proc_entry("kuzdriver", NULL);
  if (mydev) {
    for (i = 0; i < NUM_PARTITIONS; i++) {
      struct kuz_partition *p = &mydev->parts[i];
      if (!p->sysfs_ready)
        continue;
      sysfs_remove_group(&p->kobj, &part_attr_group);
      kobject_del(&p->kobj);
      kobject_put(&p->kobj);
    }
    if (mydev->sysfs_dev)
      device_destroy(kuzdriver_class, 0);
    if (kuzdriver_class)
      class_destroy(kuzdriver_class);
    myblock_free_device();
    unregister_blkdev(mydev->major, DEVICE_NAME);
    kfree(mydev);
    mydev = NULL;
  }
  return ret;
}

static void __exit myblock_exit(void) {
  int i;

  pr_info(DRIVER_NAME ": unloading\n");

  if (mydev) {
    remove_proc_entry("kuzdriver", NULL);

    for (i = 0; i < NUM_PARTITIONS; i++) {
      struct kuz_partition *p = &mydev->parts[i];
      if (!p->sysfs_ready)
        continue;
      sysfs_remove_group(&p->kobj, &part_attr_group);
      kobject_del(&p->kobj);
      kobject_put(&p->kobj);
    }

    if (mydev->sysfs_dev)
      device_destroy(kuzdriver_class, 0);
    if (kuzdriver_class)
      class_destroy(kuzdriver_class);

    myblock_free_device();
    unregister_blkdev(mydev->major, DEVICE_NAME);
    kfree(mydev);
    mydev = NULL;
  }
  pr_info(DRIVER_NAME ": unloaded\n");
}

module_init(myblock_init);
module_exit(myblock_exit);