#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/bio.h>

#define DRIVER_NAME         "KuzDriver"
#define DEVICE_NAME         "KuzEncDev"

#define NUM_PARTITIONS      3
#define PARTITION_SIZE_MB   100
#define PARTITION_SIZE_BYTES (PARTITION_SIZE_MB * 1024ULL * 1024ULL)
#define PARTITION_SIZE_SECT  (PARTITION_SIZE_BYTES / 512)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("H8SM");
MODULE_DESCRIPTION("Block device driver");
MODULE_VERSION("0.1");

struct myblock_device {
	struct gendisk          *gd;
	u8                      *data;
	int                      index;
};

static struct myblock_device *mydevs[NUM_PARTITIONS];
static int major_number;

// block_device_operations

static int myblock_open(struct gendisk *disk, blk_mode_t mode)
{
	pr_info(DRIVER_NAME ": %s opened (mode=0x%x)\n",
		disk->disk_name, mode);
	return 0;
}

static void myblock_release(struct gendisk *disk)
{
	pr_info(DRIVER_NAME ": %s closed\n", disk->disk_name);
}

static void myblock_submit_bio(struct bio *bio)
{
	struct myblock_device *dev = bio->bi_bdev->bd_disk->private_data;
	struct bvec_iter iter;
	struct bio_vec bvec;

	if (bio->bi_iter.bi_sector + bio_sectors(bio) > PARTITION_SIZE_SECT) {
		pr_err(DRIVER_NAME ": %s: request beyond device end\n",
		       dev->gd->disk_name);
		bio_io_error(bio);
		return;
	}

	bio_for_each_segment(bvec, bio, iter) {
		void *iovec_mem;
		unsigned int len = bvec.bv_len;
		unsigned int dev_offset = iter.bi_sector * 512;

		iovec_mem = kmap_local_page(bvec.bv_page);
		if (!iovec_mem) {
			pr_err(DRIVER_NAME ": kmap failed\n");
			bio_io_error(bio);
			return;
		}
		iovec_mem += bvec.bv_offset;

		if (bio_op(bio) == REQ_OP_WRITE)
			memcpy(dev->data + dev_offset, iovec_mem, len);
		else
			memcpy(iovec_mem, dev->data + dev_offset, len);

		kunmap_local(iovec_mem - bvec.bv_offset);
	}

	bio_endio(bio);
}

static const struct block_device_operations myblock_fops = {
	.owner      = THIS_MODULE,
	.open       = myblock_open,
	.release    = myblock_release,
	.submit_bio = myblock_submit_bio,
};

// free single dev

static void myblock_free_device(struct myblock_device *dev, bool disk_added)
{
	if (!dev)
		return;

	if (dev->gd) {
		if (disk_added)
			del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
	if (dev->data)
		vfree(dev->data);
	kfree(dev);
}

// init + exit

static int __init myblock_init(void)
{
	int ret;
	int i;

	pr_info(DRIVER_NAME ": loading module\n");

	major_number = register_blkdev(0, DEVICE_NAME);
	if (major_number < 0) {
		pr_err(DRIVER_NAME ": register_blkdev failed: %d\n", major_number);
		return major_number;
	}
	pr_info(DRIVER_NAME ": registered with major=%d\n", major_number);

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

		dev->data = vmalloc(PARTITION_SIZE_BYTES);
		if (!dev->data) {
			kfree(dev);
			ret = -ENOMEM;
			goto err_cleanup;
		}
		memset(dev->data, 0, PARTITION_SIZE_BYTES);

		pr_info(DRIVER_NAME ": [%d] calling blk_alloc_disk\n", i);
		dev->gd = blk_alloc_disk(&lim, NUMA_NO_NODE);
		if (IS_ERR(dev->gd)) {
			ret = PTR_ERR(dev->gd);
			pr_err(DRIVER_NAME ": blk_alloc_disk failed: %d\n", ret);
			vfree(dev->data);
			kfree(dev);
			goto err_cleanup;
		}

		dev->gd->major        = major_number;
		dev->gd->first_minor  = i;
		dev->gd->minors       = 1;
		dev->gd->fops         = &myblock_fops;
		dev->gd->private_data = dev;

		snprintf(dev->gd->disk_name, DISK_NAME_LEN, "%s%d",
				DEVICE_NAME, i);
		set_capacity(dev->gd, PARTITION_SIZE_SECT);

		pr_info(DRIVER_NAME ": [%d] calling add_disk\n", i);
		ret = add_disk(dev->gd);
		if (ret) {
			pr_err(DRIVER_NAME ": add_disk failed: %d\n", ret);
			myblock_free_device(dev, false);
			goto err_cleanup;
		}

		mydevs[i] = dev;
		pr_info(DRIVER_NAME ": /dev/%s registered\n", dev->gd->disk_name);
	}
	pr_info(DRIVER_NAME ": all %d partitions registered\n", NUM_PARTITIONS);
	return 0;

err_cleanup:
	for (i = 0; i < NUM_PARTITIONS; i++) {
		if (mydevs[i]) {
			myblock_free_device(mydevs[i], true);
			mydevs[i] = NULL;
		}
	}
	unregister_blkdev(major_number, DEVICE_NAME);
	return ret;
}

static void __exit myblock_exit(void)
{
	int i;

	pr_info(DRIVER_NAME ": unloading module\n");

	for (i = 0; i < NUM_PARTITIONS; i++) {
		if (mydevs[i]) {
			myblock_free_device(mydevs[i], true);
			mydevs[i] = NULL;
		}
	}

	unregister_blkdev(major_number, DEVICE_NAME);
	pr_info(DRIVER_NAME ": unloaded\n");
}

module_init(myblock_init);
module_exit(myblock_exit);