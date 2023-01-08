#include <linux/module.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/interrupt.h>

#include "casinodrv.h"


static dev_t casinodev_devno;
static struct casinodev_device *casinodev_devices[CASINODRV_MAX_DEVICES];
static DEFINE_MUTEX(casinodev_devices_lock);
static struct class casinodev_class = {
    .name = "casinodev",
    .owner = THIS_MODULE,
};

static inline void casinodev_iow(struct casinodev_device *dev, uint32_t reg, uint32_t val) {
    iowrite32(val, dev->bar + reg);
}

static inline uint32_t casinodev_ior(struct casinodev_device *dev, uint32_t reg) {
    uint32_t res = ioread32(dev->bar + reg);
    return res;
}

static void __bind_slot(struct casinodev_device *dev, int slot, struct casinodev_buffer *buf) {
    struct casinodev_cmd cmd;
    dma_addr_t pt_addr = buf->pt->pt.dev;
    cmd.header = CASINODEV_USER_CMD_BIND_SLOT_HEADER(slot, buf->seed, buf->type);
    cmd.data[0] = pt_addr;
    cmd.data[1] = pt_addr >> 32;
    BUG_ON((cmd.data[0] | ((dma_addr_t)cmd.data[1] << 32)) != pt_addr);

    casinodev_iow(dev, CMD_MANUAL_FEED, cmd.header);
    casinodev_iow(dev, CMD_MANUAL_FEED, cmd.data[0]);
    casinodev_iow(dev, CMD_MANUAL_FEED, cmd.data[1]);
}

static void __unbind_slot(struct casinodev_device *dev, int slot) {
    struct casinodev_cmd cmd;
    cmd.header = CASINODEV_USER_CMD_UNBIND_SLOT_HEADER(slot);
    casinodev_iow(dev, CMD_MANUAL_FEED, cmd.header);
}

static void get_cmd_portion(struct casinodev_device *dev) {
    unsigned long flags;
    spin_lock_irqsave(&dev->slock, flags);
    while (!dev->ready) {
        spin_unlock_irqrestore(&dev->slock, flags);
        wait_event(dev->entry_wq, dev->ready);
        spin_lock_irqsave(&dev->slock, flags);
    }
    dev->ready = 0;
    spin_unlock_irqrestore(&dev->slock, flags);
}

static int cmd_portion_end(struct casinodev_device *dev) {
    unsigned long flags;
    int ret = 0;
    spin_lock_irqsave(&dev->slock, flags);
    while (!dev->fence_reached) {
        spin_unlock_irqrestore(&dev->slock, flags);
        wait_event(dev->fence_wq, dev->fence_reached);
        spin_lock_irqsave(&dev->slock, flags);
    }
    if (dev->failed) {
        ret = 1;
        dev->failed = 0;
    }
    dev->ready = 1;
    wake_up(&dev->entry_wq);
    spin_unlock_irqrestore(&dev->slock, flags);
    return ret;
}

static void reset_dev(struct casinodev_device *dev) {
    casinodev_iow(dev, CASINODEV_ENABLE, 0);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, 0);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, CASINODEV_INTR_ALL);
    casinodev_iow(dev, CASINODEV_ENABLE, 1);
}


static irqreturn_t casinodev_isr(int irq, void *opaque) {
    struct casinodev_device *dev = opaque;
    unsigned long flags;
    uint32_t istatus;
    int error = 0;
    spin_lock_irqsave(&dev->slock, flags);
    // pr_info(CASINODRV_PREF " >> casinodev isr\n");
    istatus = casinodev_ior(dev, CASINODEV_INTR) & casinodev_ior(dev, CASINODEV_INTR_ENABLE);
    if (CASINODEV_INTR_FEED_ERROR & istatus) {
        BUG();
        casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_FEED_ERROR);
        // pr_warn(CASINODRV_PREF "feed error\n");
        error |= CASINODEV_INTR_FEED_ERROR;
    }
    if (CASINODEV_INTR_CMD_ERROR & istatus) {
        casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_CMD_ERROR);
        // pr_warn(CASINODRV_PREF "cmd error\n");
        error |= CASINODEV_INTR_CMD_ERROR;
    }
    if (CASINODEV_INTR_MEM_ERROR & istatus) {
        casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_MEM_ERROR);
        // pr_warn(CASINODRV_PREF "mem error\n");
        error |= CASINODEV_INTR_MEM_ERROR;
    }
    if (CASINODEV_INTR_SLOT_ERROR & istatus) {
        casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_SLOT_ERROR);
        // pr_warn(CASINODRV_PREF "slot error\n");
        error |= CASINODEV_INTR_SLOT_ERROR;
    }
    if (error) {
        dev->failed = 1;
        reset_dev(dev);
    } else if (CASINODEV_INTR_FENCE_WAIT & istatus) {
        // pr_info(CASINODRV_PREF "fence wait\n");
        casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_FENCE_WAIT);
        dev->fence_reached = 1;
        wake_up(&dev->fence_wq);
    }
    spin_unlock_irqrestore(&dev->slock, flags);
    return IRQ_RETVAL(istatus);
}


static int casinodev_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id) {
    int err, i;

    struct casinodev_device *dev = kzalloc(sizeof *dev, GFP_KERNEL);
    if (!dev) {
        err = -ENOMEM;
        goto out_alloc;
    }
    pci_set_drvdata(pdev, dev);
    dev->pdev = pdev;

    spin_lock_init(&dev->slock);
	init_waitqueue_head(&dev->entry_wq);
	init_waitqueue_head(&dev->fence_wq);
    sema_init(&dev->slot_sem, CASINODRV_NUM_SLOTS);

    /* Allocate a free index. */
    mutex_lock(&casinodev_devices_lock);
    for (i = 0; i < CASINODRV_MAX_DEVICES; i++)
        if (!casinodev_devices[i])
            break;
    if (i == CASINODRV_MAX_DEVICES) {
        err = -ENOSPC;
        mutex_unlock(&casinodev_devices_lock);
        goto out_slot;
    }
    casinodev_devices[i] = dev;
    dev->idx = i;
    mutex_unlock(&casinodev_devices_lock);
    pr_info(CASINODRV_PREF "loading /dev/casino%d\n", i);

    /* Enable hardware resources.  */
    if ((err = pci_enable_device(pdev)))
        goto out_enable;

    if ((err = pci_set_dma_mask(pdev, DMA_BIT_MASK(CASINODRV_ADDR_SIZE))))
        goto out_mask;
    if ((err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(CASINODRV_ADDR_SIZE))))
        goto out_mask;
    pci_set_master(pdev);

    if ((err = pci_request_regions(pdev, "casinodev")))
        goto out_regions;
    
    /* Map the BAR0  */
    if (!(dev->bar = pci_iomap(pdev, 0, 0))) {
        err = -ENOMEM;
        goto out_bar;
    }

    /* Connect the IRQ line.  */
    if ((err = request_irq(pdev->irq, casinodev_isr, IRQF_SHARED, CASINODRV_NAME, dev)))
        goto out_irq;

    dev->ready = 1;
    dev->failed = 0;
    dev->fence_reached = 0;
    dev->fence_val = 0;
    casinodev_iow(dev, CASINODEV_INTR, CASINODEV_INTR_ALL);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, CASINODEV_INTR_ALL);
    casinodev_iow(dev, CASINODEV_ENABLE, 1);
    casinodev_iow(dev, CASINODEV_CMD_FENCE_LAST, 0);

    /* Unbind all slots */
    for (i = 0; i < CASINODRV_NUM_SLOTS; i++) {
        __unbind_slot(dev, i);
    }
    
    /* We're live.  Let's export the cdev.  */
    cdev_init(&dev->cdev, &casinodev_file_ops);
    if ((err = cdev_add(&dev->cdev, casinodev_devno + dev->idx, 1)))
        goto out_cdev;

    /* And register it in sysfs.  */
    dev->dev = device_create(&casinodev_class,
            &dev->pdev->dev, casinodev_devno + dev->idx, dev,
            "casino%d", dev->idx);
    if (IS_ERR(dev->dev)) {
        printk(KERN_ERR CASINODRV_PREF "failed to register subdevice\n");
        /* too bad. */
        dev->dev = 0;
    }

    return 0;

out_cdev:
    casinodev_iow(dev, CASINODEV_ENABLE, 0);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, 0);
    free_irq(pdev->irq, dev);
out_irq:
    pci_iounmap(pdev, dev->bar);
out_bar:
    pci_release_regions(pdev);
out_regions:
out_mask:
    pci_disable_device(pdev);
out_enable:
    mutex_lock(&casinodev_devices_lock);
    casinodev_devices[dev->idx] = 0;
    mutex_unlock(&casinodev_devices_lock);
out_slot:
    kfree(dev);
out_alloc:
    return err;
}

static void casinodev_remove(struct pci_dev *pdev) {
    struct casinodev_device *dev = pci_get_drvdata(pdev);
    if (dev->dev) {
        device_destroy(&casinodev_class, casinodev_devno + dev->idx);
    }
    cdev_del(&dev->cdev);

    casinodev_iow(dev, CASINODEV_ENABLE, 0);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, 0);
    free_irq(pdev->irq, dev);
    pci_iounmap(pdev, dev->bar);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    mutex_lock(&casinodev_devices_lock);
    casinodev_devices[dev->idx] = 0;
    mutex_unlock(&casinodev_devices_lock);
    kfree(dev);
}

static int casinodev_suspend(struct pci_dev *pdev, pm_message_t state) {
	struct casinodev_device *dev = pci_get_drvdata(pdev);
    get_cmd_portion(dev);
    casinodev_iow(dev, CASINODEV_ENABLE, 0);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, 0);
    return 0;
}

static int casinodev_resume(struct pci_dev *pdev) {
    unsigned long flags;
	struct casinodev_device *dev = pci_get_drvdata(pdev);
	spin_lock_irqsave(&dev->slock, flags);
    casinodev_iow(dev, CASINODEV_INTR_ENABLE, CASINODEV_INTR_ALL);
    casinodev_iow(dev, CASINODEV_ENABLE, 1);
    dev->ready = 1;
    wake_up(&dev->entry_wq);
	spin_unlock_irqrestore(&dev->slock, flags);
    return 0;
}

static struct pci_device_id casinodev_pciids[] = {
    { PCI_DEVICE(CASINODEV_VENDOR_ID, CASINODEV_DEVICE_ID) },
    { 0 }
};

static struct pci_driver casinodev_pci_driver = {
    .name = "casinodev",
    .id_table = casinodev_pciids,
    .probe = casinodev_probe,
    .remove = casinodev_remove,
    .suspend = casinodev_suspend,
    .resume = casinodev_resume,
};


// PCIDEV

int pcidev_init(void) {
    int err;
    if ((err = alloc_chrdev_region(&casinodev_devno, 0, CASINODRV_MAX_DEVICES, "casinodev")))
        goto err_chrdev;
    if ((err = class_register(&casinodev_class)))
        goto err_class;
    if ((err = pci_register_driver(&casinodev_pci_driver)))
        goto err_pci;
    return 0;

err_pci:
    class_unregister(&casinodev_class);
err_class:
    unregister_chrdev_region(casinodev_devno, CASINODRV_MAX_DEVICES);
err_chrdev:
    return err;
}

void pcidev_exit(void) {
    pci_unregister_driver(&casinodev_pci_driver);
    class_unregister(&casinodev_class);
    unregister_chrdev_region(casinodev_devno, CASINODRV_MAX_DEVICES);
}


// SLOTS

int get_slot(struct casinodev_device *dev, struct casinodev_buffer *buf) {
    unsigned long i, flags;
    down(&dev->slot_sem);
    spin_lock_irqsave(&dev->slock, flags);
    for (i = 0; i < CASINODRV_NUM_SLOTS; i++) {
        if (!dev->slots[i]) {
            dev->slots[i] = buf;
            break;
        }
    }
    spin_unlock_irqrestore(&dev->slock, flags);
    BUG_ON(i == CASINODRV_NUM_SLOTS);
    return i;
}

void put_slot(struct casinodev_device *dev, int slot) {
    unsigned long flags;
    spin_lock_irqsave(&dev->slock, flags);
    BUG_ON(!dev->slots[slot]);
    dev->slots[slot] = NULL;
    spin_unlock_irqrestore(&dev->slock, flags);
    up(&dev->slot_sem);
}


// EXECUTOR

void bind_slot(struct casinodev_device *dev, int slot, struct casinodev_buffer *buf) {
    unsigned long flags;
    get_cmd_portion(dev);
    spin_lock_irqsave(&dev->slock, flags);
    __bind_slot(dev, slot, buf);
    dev->ready = 1;
    wake_up(&dev->entry_wq);
    spin_unlock_irqrestore(&dev->slock, flags);
}

void unbind_slot(struct casinodev_device *dev, int slot) {
    unsigned long flags;
    get_cmd_portion(dev);
    spin_lock_irqsave(&dev->slock, flags);
    __unbind_slot(dev, slot);
    dev->ready = 1;
    wake_up(&dev->entry_wq);
    spin_unlock_irqrestore(&dev->slock, flags);
}

void seed_increment(struct casinodev_device *dev, int si) {
    unsigned long flags;
    spin_lock_irqsave(&dev->slock, flags);
    dev->seed_increment = si;
    casinodev_iow(dev, CASINODEV_INCREMENT_SEED, si);
    spin_unlock_irqrestore(&dev->slock, flags);
}

int exec(struct casinodev_device *dev, struct casinodev_cmd_feeder *feeder, int slot) {
    unsigned long flags;
    struct casinodev_cmd cmd;
    unsigned int cmd_free, len = 0;
    int ret = 0;

    while (len < feeder->len) {
        get_cmd_portion(dev);
        spin_lock_irqsave(&dev->slock, flags);
        cmd_free = casinodev_ior(dev, CMD_MANUAL_FREE);
        while (cmd_free >= 4 && len < feeder->len) {
            cmd = feeder->feed(feeder->src);
            if ((cmd.header & CASINODEV_CMD_TYPE_MASK) == CASINODEV_USER_CMD_TYPE_BIND_SLOT) {
                // not supported
                cmd_free -= 3;
                len += 3;
            } else {
                if ((cmd.header & CASINODEV_CMD_TYPE_MASK) == CASINODEV_USER_CMD_TYPE_GET_CARDS) {
                    cmd.header = (cmd.header & ((1 << 24) - 1)) | (slot << 24);
                } else if ((cmd.header & CASINODEV_CMD_TYPE_MASK) == CASINODEV_USER_CMD_TYPE_NEW_DECK) {
                    cmd.header = (cmd.header & ((1 << 4) - 1)) | (slot << 4);
                }
                casinodev_iow(dev, CMD_MANUAL_FEED, cmd.header);
                cmd_free -= 1;
                len += 1;
            }
        }
        dev->fence_val = (dev->fence_val + 1) % (1 << 28);
        dev->fence_reached = 0;
        casinodev_iow(dev, CASINODEV_CMD_FENCE_WAIT, dev->fence_val);
        casinodev_iow(dev, CMD_MANUAL_FEED, CASINODEV_USER_CMD_FENCE_HEADER(dev->fence_val));
        spin_unlock_irqrestore(&dev->slock, flags);
        if ((ret = cmd_portion_end(dev))) {
            break;
        }
    }
    return ret;
}