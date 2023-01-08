#include <linux/module.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/interrupt.h>
#include <asm/set_memory.h>

#include "casinodrv.h"

#define BUFFER_FILE_FLAGS O_RDWR

// CASINODEV_BUFFER FILEOPS

static ssize_t casinodev_buffer_write(struct file *file, const char __user *user_buf,
        size_t len, loff_t *off) {
    void* data;
    ssize_t ret;
    struct casinodev_task *t;
    struct casinodev_buffer *buf = file->private_data;
    struct casinodev_context *ctx = buf->ctx;

    if (len % 4) {
        ret = -EINVAL;
        goto buf_write_inval;
    }
    if (!(data = kmalloc(len, GFP_KERNEL))) {
        ret = -ENOMEM;
        goto buf_write_mem;
    }
    if (copy_from_user(data, user_buf, len)) {
        ret = -EFAULT;
        goto buf_write_copy;
    }
    if ((ret = task_create_write(&t, ctx, buf, data, len))) {
        goto buf_write_task_create;
    }

    spin_lock(&ctx->slock);
    list_add_tail(&t->lh, &ctx->tasks);
    spin_unlock(&ctx->slock);

    return len;

buf_write_task_create:
buf_write_copy:
    kfree(data);
buf_write_mem:
buf_write_inval:
    return ret;
}

static long casinodev_buffer_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct casinodev_buffer *buf = file->private_data;
    struct casinodev_ioctl_seed s;
    if (cmd != CASINODEV_BUFFER_IOCTL_SEED)
        return -ENOTTY;
    if (copy_from_user(&s, (const void __user *) arg, sizeof s))
        return -EFAULT;
    buf->seed = s.seed;
    if (buf->persistent_slot != CASINODRV_NO_SLOT) {
        buf->persistent_slot = CASINODRV_NO_SLOT;
        unbind_slot(buf->dev, buf->persistent_slot);
        put_slot(buf->dev, buf->persistent_slot);
    }
    return 0;
}

static vm_fault_t casinodev_buffer_vm_op_fault(struct vm_fault *vmf) {
    struct casinodev_pt *pt;

    BUG_ON(vmf->vma->vm_private_data == NULL);
    pt = vmf->vma->vm_private_data;
    if (vmf->pgoff >= pt->num_pages)
        return VM_FAULT_SIGBUS;

    vmf->page = virt_to_page(pt->pages[vmf->pgoff].kern);
    get_page(vmf->page);
    return 0;
}

static const struct vm_operations_struct casinodev_buffer_vm_ops = {
    .fault = casinodev_buffer_vm_op_fault,
};

static int casinodev_buffer_mmap(struct file *file, struct vm_area_struct *vma) {
    int ret = 0;
    struct casinodev_buffer *buf = file->private_data;
    if (!(vma->vm_flags & VM_SHARED))
        return -EINVAL;
    vma->vm_ops = &casinodev_buffer_vm_ops;
    vma->vm_private_data = buf->pt;
    return ret;
}

static int casinodev_buffer_release(struct inode *inode, struct file *file) {
    struct casinodev_buffer *buf = file->private_data;
    if (buf->persistent_slot != CASINODRV_NO_SLOT) {
        unbind_slot(buf->dev, buf->persistent_slot);
        put_slot(buf->dev, buf->persistent_slot);
    }
    free_casinodev_pt(buf->pt, buf->dev);
    kfree(buf->pt);
    kfree(buf);
    return 0;
}

const struct file_operations casinodev_buffer_file_ops = {
    .owner = THIS_MODULE,
    .write = casinodev_buffer_write,
    .unlocked_ioctl = casinodev_buffer_ioctl,
    .mmap = casinodev_buffer_mmap,
    .release = casinodev_buffer_release,
};


// CASINODEV CHARDEV FILEOPS

static long ioctl_create_decks(struct casinodev_context *ctx, const void __user* arg) {
    int err, fd;
    struct file *fil;
    struct casinodev_buffer *buf;
    struct casinodev_ioctl_create_decks cd;
    if (copy_from_user(&cd, arg, sizeof cd)) {
        err = -EFAULT;
        goto cd_arg;
    }
    if (cd.size < 0 || cd.size > CASINODRV_MAX_DECK_SIZE) {
        err = -EINVAL;
        goto cd_arg;
    }
    if (cd.type != FULL && cd.type != NINE_PLUS) {
        err = -EINVAL;
        goto cd_arg;
    }
    if (!(buf = kzalloc(sizeof *buf, GFP_KERNEL))) {
        err = -ENOMEM;
        goto cd_buf_alloc;
    }
    if (!(buf->pt = kzalloc(sizeof(struct casinodev_pt), GFP_KERNEL))) {
        err = -ENOMEM;
        goto cd_pt_alloc;
    }
    if ((err = alloc_casinodev_pt(buf->pt, ctx->dev, cd.size))) {
        goto cd_pt_err;
    }
    if ((fd = get_unused_fd_flags(BUFFER_FILE_FLAGS)) < 0) {
        err = fd;
        goto cd_fd_alloc;
    }
    if (IS_ERR(fil = anon_inode_getfile("casinodev_buffer", &casinodev_buffer_file_ops, buf, BUFFER_FILE_FLAGS))) {
        err = -PTR_ERR(fil);
        goto cd_inode_alloc;
    }

    buf->dev = ctx->dev;
    buf->ctx = ctx;
    buf->size = cd.size;
    buf->persistent_slot = CASINODRV_NO_SLOT;

    buf->seed = CASINODRV_INIT_SEED;
    buf->type = cd.type;

    buf->fil = fil;
    fd_install(fd, fil);

    return fd;

cd_inode_alloc:
    put_unused_fd(fd);
cd_fd_alloc:
    free_casinodev_pt(buf->pt, ctx->dev);
cd_pt_err:
    kfree(buf->pt);
cd_pt_alloc:
    kfree(buf);
cd_buf_alloc:
cd_arg:
    return err;
}

static long ioctl_run(struct casinodev_context *ctx, const void __user * arg) {
    int err;
    struct casinodev_task *t;
    struct casinodev_ioctl_run r;

    if (copy_from_user(&r, arg, sizeof r))
        return -EFAULT;
    if (ctx->failed)
        return -EIO;
    if ((err = task_create_ioctl(&t, ctx, r))) {
        return err;
    }

    spin_lock(&ctx->slock);
    list_add_tail(&t->lh, &ctx->tasks);
    spin_unlock(&ctx->slock);

    return 0;
}

static long ioctl_wait(struct casinodev_context *ctx, const void __user * arg) {
    int err = 0;
    struct casinodev_ioctl_wait w;
    struct casinodev_task *task;
    struct list_head *lh, *tmp;
    struct list_head tasks;
    if (copy_from_user(&w, arg, sizeof w)) {
        err = -EFAULT;
        goto arg_copy;
    }

    // move all but w.cnt tasks from the queue to our list `tasks`
    INIT_LIST_HEAD(&tasks);
    spin_lock(&ctx->slock);
    for (lh = &ctx->tasks; w.cnt > 0; w.cnt--) {
        lh = lh->prev;
        if (list_is_first(lh, &ctx->tasks))
            break; // we made a circle, there is nothing to wait for
    }
    list_cut_before(&tasks, &ctx->tasks, lh);
    if (ctx->failed)
        err = -EIO;
    spin_unlock(&ctx->slock);

    // run tasks one by one
    list_for_each_safe(lh, tmp, &tasks) {
		task = list_entry(lh, struct casinodev_task, lh);
        if (err != -EIO) {
            if ((err = task_execute(task))) {
                err = -EIO;
                ctx->failed = true;
            }
        }
        task_destroy(task);
    }
    
arg_copy:
    return err;
}

static long ioctl_enable_seed_increment(struct casinodev_context *ctx, const void __user * arg) {
    struct casinodev_ioctl_seed_increment si;
    if (copy_from_user(&si, arg, sizeof si)) {
        return -EFAULT;
    }
    seed_increment(ctx->dev, !!si.enable_increment);
    return 0;
}

static long casinodev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct casinodev_context *ctx = file->private_data;
    switch (cmd) {
        case CASINODEV_IOCTL_CREATE_DECKS:
            return ioctl_create_decks(ctx, (const void __user *) arg);
        case CASINODEV_IOCTL_RUN:
            return ioctl_run(ctx, (const void __user *) arg);
        case CASINODEV_IOCTL_WAIT:
            return ioctl_wait(ctx, (const void __user *) arg);
        case CASINODEV_IOCTL_ENABLE_SEED_INCREMENT:
            return ioctl_enable_seed_increment(ctx, (const void __user *) arg);
        default:
            return -ENOTTY;
    }
    return 0;
}

static int casinodev_open(struct inode *inode, struct file *file) {
    struct casinodev_device *dev = container_of(inode->i_cdev, struct casinodev_device, cdev);
    struct casinodev_context *ctx = kzalloc(sizeof *ctx, GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;
    ctx->dev = dev;
	INIT_LIST_HEAD(&ctx->tasks);
    spin_lock_init(&ctx->slock);
    file->private_data = ctx;
    return nonseekable_open(inode, file);
}

static int casinodev_release(struct inode *inode, struct file *file) {
    struct casinodev_context *ctx = file->private_data;
    kfree(ctx);
    return 0;
}

const struct file_operations casinodev_file_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = casinodev_ioctl,
    .open = casinodev_open,
    .release = casinodev_release,
};

int chardev_init(void) {
    return 0;
}

void chardev_exit(void) {}