#include <crypto/skcipher.h>
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "kuzdriver_ioctl.h"

#define DRIVER_NAME "KuzDriver"
#define DEVICE_NAME "KuzEncDev"

#define NUM_PARTITIONS 3
#define PARTITION_SIZE_MB 100
#define PARTITION_SIZE_BYTES (PARTITION_SIZE_MB * 1024ULL * 1024ULL)
#define PARTITION_SIZE_SECT (PARTITION_SIZE_BYTES / 512)

#define KUZ_IV_SIZE 16 // block size in bytes

MODULE_LICENSE("GPL");
MODULE_AUTHOR("H8SM");
MODULE_DESCRIPTION(
    "Block device driver with transparent Kuznyechik CTR encryption");
MODULE_VERSION("0.7");

struct myblock_device {
  struct gendisk *gd;
  u8 *data;
  int index;
  // state
  atomic_t locked;
  struct mutex key_lock;
  u8 key[32];
  bool key_set;
  // statistic
  atomic64_t reads;
  atomic64_t writes;
  atomic64_t bytes_read;
  atomic64_t bytes_written;
  // crypto
  struct crypto_skcipher *tfm;
  atomic_t crypto_enabled;
};

static struct myblock_device *mydevs[NUM_PARTITIONS];
static int major_number;

// block_device_operations

static int myblock_open(struct gendisk *disk, blk_mode_t mode) {
  pr_info(DRIVER_NAME ": %s opened (mode=0x%x)\n", disk->disk_name, mode);
  return 0;
}

static void myblock_release(struct gendisk *disk) {
  pr_info(DRIVER_NAME ": %s closed\n", disk->disk_name);
}

// crypto stuff
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
static int myblock_crypt_data(struct myblock_device *dev, u64 sector, void *buf,
                              size_t len, bool encrypt) {
  struct scatterlist *sg;
  struct skcipher_request *req;
  u8 iv[KUZ_IV_SIZE] = {0};
  int nents, ret;

  sg = myblock_sg_from_vmalloc(buf, len, &nents);
  if (!sg) {
    pr_err(DRIVER_NAME ": %s: failed to build sg list\n", dev->gd->disk_name);
    return -ENOMEM;
  }

  req = skcipher_request_alloc(dev->tfm, GFP_KERNEL);
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

  if (ret)
    pr_err(DRIVER_NAME ": crypto_skcipher_%s failed: %d\n",
           encrypt ? "encrypt" : "decrypt", ret);

  return ret;
}

static void myblock_submit_bio(struct bio *bio) {
  struct myblock_device *dev = bio->bi_bdev->bd_disk->private_data;
  struct bvec_iter iter;
  struct bio_vec bvec;
  bool is_write = (bio_op(bio) == REQ_OP_WRITE);
  bool do_crypt = dev->key_set && atomic_read(&dev->crypto_enabled);

  if (atomic_read(&dev->locked)) {
    pr_info(DRIVER_NAME ": %s: I/O on locked device\n", dev->gd->disk_name);
    bio_io_error(bio);
    return;
  }

  if (bio->bi_iter.bi_sector + bio_sectors(bio) > PARTITION_SIZE_SECT) {
    pr_err(DRIVER_NAME ": %s: request beyond device end\n", dev->gd->disk_name);
    bio_io_error(bio);
    return;
  }

  bio_for_each_segment(bvec, bio, iter) {
    void *iovec_mem;
    unsigned int len = bvec.bv_len;
    unsigned int dev_offset = iter.bi_sector * 512;
    int ret;
    if (is_write) {
      iovec_mem = kmap_local_page(bvec.bv_page);
      if (!iovec_mem) {
        bio_io_error(bio);
        return;
      }
      iovec_mem += bvec.bv_offset;
      memcpy(dev->data + dev_offset, iovec_mem, len);
      kunmap_local(iovec_mem - bvec.bv_offset);

      if (dev->key_set) {
        if (do_crypt) {
          ret = myblock_crypt_data(dev, iter.bi_sector, dev->data + dev_offset,
                                   len, true);
          if (ret) {
            bio_io_error(bio);
            return;
          }
        }
      }
    } else {
      if (dev->key_set) {
        if (do_crypt) {
          ret = myblock_crypt_data(dev, iter.bi_sector, dev->data + dev_offset,
                                   len, false);
          if (ret) {
            bio_io_error(bio);
            return;
          }
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
  }

  if (is_write) {
    atomic64_inc(&dev->writes);
    atomic64_add(bio->bi_iter.bi_size, &dev->bytes_written);
  } else {
    atomic64_inc(&dev->reads);
    atomic64_add(bio->bi_iter.bi_size, &dev->bytes_read);
  }

  bio_endio(bio);
}

// ioctl

static int myblock_ioctl(struct block_device *bdev, blk_mode_t mode,
                         unsigned int cmd, unsigned long arg) {
  struct myblock_device *dev = bdev->bd_disk->private_data;
  void __user *argp = (void __user *)arg;

  switch (cmd) {
  case MYBLOCK_IOCTL_SET_KEY: {
    struct myblock_key k;
    int ret;

    if (copy_from_user(&k, argp, sizeof(k)))
      return -EFAULT;

    mutex_lock(&dev->key_lock);
    ret = crypto_skcipher_setkey(dev->tfm, k.key, 32);
    if (ret) {
      mutex_unlock(&dev->key_lock);
      pr_err(DRIVER_NAME ": setkey failed: %d\n", ret);
      return ret;
    }
    memcpy(dev->key, k.key, sizeof(dev->key));
    dev->key_set = true;
    mutex_unlock(&dev->key_lock);

    pr_info(DRIVER_NAME ": %s: key set\n", dev->gd->disk_name);
    return 0;
  }

  case MYBLOCK_IOCTL_LOCK:
    atomic_set(&dev->locked, 1);
    pr_info(DRIVER_NAME ": %s: locked\n", dev->gd->disk_name);
    return 0;

  case MYBLOCK_IOCTL_UNLOCK:
    atomic_set(&dev->locked, 0);
    atomic_set(&dev->crypto_enabled, 1);
    pr_info(DRIVER_NAME ": %s: unlocked\n", dev->gd->disk_name);
    return 0;

  case MYBLOCK_IOCTL_GET_STATUS: {
    struct myblock_status st;

    memset(&st, 0, sizeof(st));
    st.locked = atomic_read(&dev->locked) ? 1 : 0;
    st.reads = atomic64_read(&dev->reads);
    st.writes = atomic64_read(&dev->writes);
    st.bytes_read = atomic64_read(&dev->bytes_read);
    st.bytes_written = atomic64_read(&dev->bytes_written);
    st.crypto_enabled = atomic_read(&dev->crypto_enabled) ? 1 : 0;

    mutex_lock(&dev->key_lock);
    st.key_set = dev->key_set ? 1 : 0;
    mutex_unlock(&dev->key_lock);

    if (copy_to_user(argp, &st, sizeof(st)))
      return -EFAULT;
    return 0;
  }
  case MYBLOCK_IOCTL_ENABLE_CRYPTO:
    atomic_set(&dev->crypto_enabled, 1);
    pr_info(DRIVER_NAME ": %s: crypto enabled\n", dev->gd->disk_name);
    return 0;

  case MYBLOCK_IOCTL_DISABLE_CRYPTO:
    atomic_set(&dev->crypto_enabled, 0);
    pr_info(DRIVER_NAME ": %s: crypto disabled\n", dev->gd->disk_name);
    return 0;
  default:
    return -ENOTTY;
  }
}

// procfs

static void kuzdriver_dump_buffer(struct seq_file *m,
                                  struct myblock_device *dev) {
  int i;
  seq_puts(m, "  buffer[0..31]: ");
  for (i = 0; i < 32; i++)
    seq_printf(m, "%02x",
               dev->data[i]); // TODO: make some spinlock or something
  seq_puts(m, "\n");
}

static int kuzdriver_proc_show(struct seq_file *m, void *v) {
  int i;

  seq_puts(m, "KuzDriver status\n");
  seq_puts(m, "================\n\n");

  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct myblock_device *dev = mydevs[i];
    bool key_set;

    if (!dev)
      continue;

    mutex_lock(&dev->key_lock);
    key_set = dev->key_set;
    mutex_unlock(&dev->key_lock);

    seq_printf(m, "partition %d: /dev/%s\n", i, dev->gd->disk_name);
    seq_printf(m, "  capacity:       %u MiB\n", PARTITION_SIZE_MB);
    seq_printf(m, "  locked:         %s\n",
               atomic_read(&dev->locked) ? "yes" : "no");
    seq_printf(m, "  key_set:        %s\n", key_set ? "yes" : "no");
    seq_printf(m, "  crypto_enabled: %s\n",
               atomic_read(&dev->crypto_enabled) ? "yes" : "no");
    seq_printf(m, "  reads:          %llu\n",
               (unsigned long long)atomic64_read(&dev->reads));
    seq_printf(m, "  writes:         %llu\n",
               (unsigned long long)atomic64_read(&dev->writes));
    seq_printf(m, "  bytes_read:     %llu\n",
               (unsigned long long)atomic64_read(&dev->bytes_read));
    seq_printf(m, "  bytes_written:  %llu\n",
               (unsigned long long)atomic64_read(&dev->bytes_written));

    kuzdriver_dump_buffer(m, dev);
    seq_puts(m, "\n");
  }
  return 0;
}

static const struct block_device_operations myblock_fops = {
    .owner = THIS_MODULE,
    .open = myblock_open,
    .release = myblock_release,
    .submit_bio = myblock_submit_bio,
    .ioctl = myblock_ioctl,
};

// free single device

static void myblock_free_device(struct myblock_device *dev, bool disk_added) {
  if (!dev)
    return;

  if (dev->gd) {
    if (disk_added)
      del_gendisk(dev->gd);
    put_disk(dev->gd);
  }
  if (dev->tfm)
    crypto_free_skcipher(dev->tfm);
  if (dev->data)
    vfree(dev->data);

  memzero_explicit(
      dev->key,
      sizeof(dev->key)); // it should be RND'ed, but i'm not certifying this
  mutex_destroy(&dev->key_lock);
  kfree(dev);
}

// init + exit

static int __init myblock_init(void) {
  int ret;
  int i;

  pr_info(DRIVER_NAME ": loading\n");

  major_number = register_blkdev(0, DEVICE_NAME);
  if (major_number < 0) {
    pr_err(DRIVER_NAME ": register_blkdev failed: %d\n", major_number);
    return major_number;
  }
  pr_info(DRIVER_NAME ": major=%d\n", major_number);

  for (i = 0; i < NUM_PARTITIONS; i++) {
    struct myblock_device *dev;
    struct queue_limits lim = {
        .physical_block_size = PAGE_SIZE,
        .features = BLK_FEAT_SYNCHRONOUS,
    };

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) {
      ret = -ENOMEM;
      goto err_cleanup;
    }
    dev->index = i;

    atomic_set(&dev->locked, 0);
    atomic64_set(&dev->reads, 0);
    atomic64_set(&dev->writes, 0);
    atomic64_set(&dev->bytes_read, 0);
    atomic64_set(&dev->bytes_written, 0);
    mutex_init(&dev->key_lock);
    dev->key_set = false;

    dev->data = vmalloc(PARTITION_SIZE_BYTES);
    if (!dev->data) {
      pr_err(DRIVER_NAME ": vmalloc failed for %d\n", i);
      mutex_destroy(&dev->key_lock);
      kfree(dev);
      ret = -ENOMEM;
      goto err_cleanup;
    }
    memset(dev->data, 0, PARTITION_SIZE_BYTES);

    dev->tfm = crypto_alloc_skcipher("ctr(kuznyechik)", 0, 0);
    if (IS_ERR(dev->tfm)) {
      ret = PTR_ERR(dev->tfm);
      pr_err(DRIVER_NAME ": crypto_alloc_skcipher failed: %d\n", ret);
      dev->tfm = NULL;
      vfree(dev->data);
      mutex_destroy(&dev->key_lock);
      kfree(dev);
      goto err_cleanup;
    }
    pr_info(DRIVER_NAME ": [%d] crypto tfm created (ivsize=%u)\n", i,
            crypto_skcipher_ivsize(dev->tfm));

    dev->gd = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if (IS_ERR(dev->gd)) {
      ret = PTR_ERR(dev->gd);
      pr_err(DRIVER_NAME ": blk_alloc_disk failed: %d\n", ret);
      dev->gd = NULL;
      myblock_free_device(dev, false);
      goto err_cleanup;
    }

    dev->gd->major = major_number;
    dev->gd->first_minor = i;
    dev->gd->minors = 1;
    dev->gd->fops = &myblock_fops;
    dev->gd->private_data = dev;

    snprintf(dev->gd->disk_name, DISK_NAME_LEN, "%s%d", DEVICE_NAME, i);
    set_capacity(dev->gd, PARTITION_SIZE_SECT);

    ret = add_disk(dev->gd);
    if (ret) {
      pr_err(DRIVER_NAME ": add_disk failed: %d\n", ret);
      myblock_free_device(dev, false);
      goto err_cleanup;
    }

    mydevs[i] = dev;
    pr_info(DRIVER_NAME ": /dev/%s registered\n", dev->gd->disk_name);
  }

  if (!proc_create_single("kuzdriver", 0444, NULL, kuzdriver_proc_show)) {
    pr_err(DRIVER_NAME ": failed to create /proc/kuzdriver\n");
    ret = -ENOMEM;
    goto err_cleanup;
  }
  pr_info(DRIVER_NAME ": /proc/kuzdriver created\n");

  pr_info(DRIVER_NAME ": all %d partitions registered\n", NUM_PARTITIONS);
  return 0;

err_cleanup:
  remove_proc_entry("kuzdriver", NULL); // will be fine even if there is no file
  for (i = 0; i < NUM_PARTITIONS; i++) {
    if (mydevs[i]) {
      myblock_free_device(mydevs[i], true);
      mydevs[i] = NULL;
    }
  }
  unregister_blkdev(major_number, DEVICE_NAME);
  return ret;
}

static void __exit myblock_exit(void) {
  int i;

  pr_info(DRIVER_NAME ": unloading\n");
  for (i = 0; i < NUM_PARTITIONS; i++) {
    if (mydevs[i]) {
      myblock_free_device(mydevs[i], true);
      mydevs[i] = NULL;
    }
  }
  remove_proc_entry("kuzdriver", NULL);
  unregister_blkdev(major_number, DEVICE_NAME);
  pr_info(DRIVER_NAME ": unloaded\n");
}

module_init(myblock_init);
module_exit(myblock_exit);