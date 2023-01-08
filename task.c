#include <linux/file.h>
#include <linux/fs.h>
#include "casinodrv.h"

struct feed_from_write_data {
    unsigned int off;
    uint32_t *data;
};

static struct casinodev_cmd feed_from_write(void* src) {
    struct casinodev_cmd cmd;
    struct feed_from_write_data *data = src;
    cmd.header = data->data[data->off++];
    if ((cmd.header & CASINODEV_CMD_TYPE_MASK) == CASINODEV_USER_CMD_TYPE_BIND_SLOT) {
        cmd.data[0] = data->data[data->off++];
        cmd.data[1] = data->data[data->off++];
    }
    return cmd;
}

static inline struct fd buffer_fdget(unsigned int fd, struct casinodev_device *dev) {
    struct casinodev_buffer *buf;
    struct fd ret = fdget(fd);

    // fd is valid
    if (ret.file == NULL)
        goto buf_fdget_no_fd;
    // fd is casinodev buffer chardev
    if (ret.file->f_op != &casinodev_buffer_file_ops)
        goto buf_fdget_fail;
    // the buffer has the same pcidev
    buf = ret.file->private_data;
    if (buf->dev != dev)
        goto buf_fdget_fail;
    
    return ret;

buf_fdget_fail:
    fdput(ret);
    ret.file = NULL;
buf_fdget_no_fd:
    // pr_warn(CASINODRV_PREF "buffer fdget failed\n");
    return ret;
}

static inline struct casinodev_buffer* fd_to_buffer(struct fd fd) {
    return fd.file->private_data;
}

int task_create_ioctl(struct casinodev_task **ret, struct casinodev_context *ctx, struct casinodev_ioctl_run r) {
    int err;
    struct casinodev_task *t;
    if ((r.addr & 0x3) || (r.size & 0x3)) {
        err = -EINVAL;
        goto arg_err;
    }
    if (!(t = kmalloc(sizeof(struct casinodev_task), GFP_KERNEL))) {
        err = -ENOMEM;
        goto task_alloc;
    }
    t->data.buf_fd_cmd = buffer_fdget(r.cfd, ctx->dev);
    if (!t->data.buf_fd_cmd.file) {
        err = -EINVAL;
        goto fdget_cfd;
    }
    t->data.buf_fd_output = buffer_fdget(r.bfd, ctx->dev);
    if (!t->data.buf_fd_output.file) {
        err = -EINVAL;
        goto fdget_bfd;
    }
    t->type = TASK_TYPE_IOCTL;
    t->ctx = ctx;
    t->data.instr_off = r.addr;
    t->data.instr_len = r.size;
    *ret = t;
    return 0;

fdget_bfd:
    fdput(t->data.buf_fd_cmd);
fdget_cfd:
    kfree(t);
task_alloc:
arg_err:
    // pr_warn(CASINODRV_PREF "task create failed (ioctl)\n");
    return err;
}

int task_create_write(struct casinodev_task **ret, struct casinodev_context *ctx,
        struct casinodev_buffer *buf, char* write_data, unsigned int len) {
    struct casinodev_task *t;
    if (!(t = kmalloc(sizeof(struct casinodev_task), GFP_KERNEL))) {
        // pr_warn(CASINODRV_PREF "task create failed (write)\n");
        return -ENOMEM;
    }
    get_file(buf->fil);

    t->type = TASK_TYPE_WRITE;
    t->ctx = ctx;
    t->data.write_buf = buf;
    t->data.write_data = write_data;
    t->data.write_len = len;
    *ret = t;
    return 0;
}

struct feed_from_buffer_data {
    unsigned int off;
    struct casinodev_pt *pt;
};

static struct casinodev_cmd feed_from_buffer(void* src) {
    struct casinodev_cmd cmd;
    struct feed_from_buffer_data *data = src;
    cmd.header = *(uint32_t*)(data->pt->pages[data->off / CASINODEV_PAGE_SIZE].kern + (data->off % CASINODEV_PAGE_SIZE));
    data->off += sizeof(uint32_t);
    if ((cmd.header & CASINODEV_CMD_TYPE_MASK) == CASINODEV_USER_CMD_TYPE_BIND_SLOT) {
        cmd.data[0] = *(uint32_t*)(data->pt->pages[data->off / CASINODEV_PAGE_SIZE].kern + (data->off % CASINODEV_PAGE_SIZE));
        data->off += sizeof(uint32_t);
        cmd.data[1] = *(uint32_t*)(data->pt->pages[data->off / CASINODEV_PAGE_SIZE].kern + (data->off % CASINODEV_PAGE_SIZE));
        data->off += sizeof(uint32_t);
    }
    return cmd;
}

static int task_execute_ioctl(struct casinodev_task *t) {
    int err, slot;
    struct casinodev_buffer *buf_output, *buf_cmd;
    struct feed_from_buffer_data feed_data;
    struct casinodev_cmd_feeder feeder;

    buf_output = fd_to_buffer(t->data.buf_fd_output);
    buf_cmd = fd_to_buffer(t->data.buf_fd_cmd);

    slot = get_slot(t->ctx->dev, buf_output);
    bind_slot(t->ctx->dev, slot, buf_output);

    feed_data.off = t->data.instr_off;
    feed_data.pt = buf_cmd->pt;
    feeder.feed = feed_from_buffer;
    feeder.len = t->data.instr_len / sizeof(uint32_t);
    feeder.src = &feed_data;
    err = exec(t->ctx->dev, &feeder, slot);

    unbind_slot(t->ctx->dev, slot);
    put_slot(t->ctx->dev, slot);

    return err;
}

static int task_execute_write(struct casinodev_task *t) {
    int err;
    struct feed_from_write_data feed_data;
    struct casinodev_cmd_feeder feeder;
    struct casinodev_buffer *buf = t->data.write_buf;

    if (buf->persistent_slot == CASINODRV_NO_SLOT) {
        buf->persistent_slot = get_slot(buf->dev, buf);
        bind_slot(buf->dev, buf->persistent_slot, buf);
    }

    feed_data.off = 0;
    feed_data.data = (uint32_t*) t->data.write_data;
    feeder.feed = feed_from_write;
    feeder.len = t->data.write_len / sizeof(uint32_t);
    feeder.src = &feed_data;
    err = exec(buf->dev, &feeder, buf->persistent_slot);

    return err;
}

int task_execute(struct casinodev_task *t) {
    if (t->type == TASK_TYPE_IOCTL) {
        return task_execute_ioctl(t);
    } else {
        return task_execute_write(t);
    }
}

void task_destroy(struct casinodev_task *t) {
    if (t->type == TASK_TYPE_IOCTL) {
        fdput(t->data.buf_fd_cmd);
        fdput(t->data.buf_fd_output);
    } else {
        fput(t->data.write_buf->fil);
        kfree(t->data.write_data);
    }
    kfree(t);
}
