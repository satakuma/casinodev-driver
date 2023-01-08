#ifndef CASINODRV_H
#define CASINODRV_H

#include <linux/file.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/semaphore.h>

#include "casinodev.h"

#define CASINODRV_MAX_DEVICES 256
#define CASINODRV_NUM_SLOTS 16
#define CASINODRV_ADDR_SIZE 40

#define CASINODRV_PTE_NUM 1024
#define CASINODRV_MAX_DECK_SIZE (CASINODEV_PAGE_SIZE * CASINODRV_PTE_NUM)

#define CASINODRV_INIT_SEED 42

#define CASINODRV_NO_SLOT (-1)

#define CASINODRV_NAME "casinodev"
#define CASINODRV_PREF "[casinodev] "

struct casinodev_buffer;

struct casinodev_device {
	struct pci_dev *pdev;
	struct cdev cdev;
	int idx;
	struct device *dev;
	void __iomem *bar;
	spinlock_t slock;
	struct semaphore slot_sem;
	wait_queue_head_t entry_wq;
	wait_queue_head_t fence_wq;
	int ready;
	bool failed;
	bool fence_reached;
	int fence_val;

	struct casinodev_buffer *slots[CASINODRV_NUM_SLOTS];
	bool seed_increment;
};

struct casinodev_context {
	struct casinodev_device *dev;
	spinlock_t slock;
	struct list_head tasks;
	bool failed;
};

struct casinodev_page {
	void *kern;
	dma_addr_t dev;
};

struct casinodev_pt {
	int num_pages;
	struct casinodev_page *pages;
	struct casinodev_page pt;
};

struct casinodev_buffer {
	struct casinodev_device *dev;
    struct casinodev_context *ctx;
	struct casinodev_pt *pt;
	struct file* fil;
	unsigned long size;
	int persistent_slot;

	enum deck_type type;
	unsigned int seed;
};

enum task_type {
	TASK_TYPE_IOCTL = 0,
	TASK_TYPE_WRITE = 1
};

struct casinodev_task {
	struct list_head lh;
	struct casinodev_context *ctx;

	enum task_type type;

	union {
		struct {
			// ioctl run data
			struct fd buf_fd_output;
			struct fd buf_fd_cmd;
			unsigned int instr_off;
			unsigned int instr_len;
		};
		struct {
			// iouring write data 
			struct casinodev_buffer* write_buf;
			char* write_data;
			unsigned int write_len;
		};
	} data;
};


struct casinodev_cmd {
	uint32_t header;
	uint32_t data[2];
};

struct casinodev_cmd_feeder {
	struct casinodev_cmd (*feed)(void* src);
	void* src;
	unsigned int len;
};


// page table

int alloc_casinodev_pt(struct casinodev_pt *pt, struct casinodev_device *dev, size_t size);

void free_casinodev_pt(struct casinodev_pt *pt, struct casinodev_device *dev);


// pcidev

int pcidev_init(void);

void pcidev_exit(void);

int get_slot(struct casinodev_device *dev, struct casinodev_buffer *buf);

void put_slot(struct casinodev_device *dev, int slot);

void bind_slot(struct casinodev_device *dev, int slot, struct casinodev_buffer *buf);

void unbind_slot(struct casinodev_device *dev, int slot);

void seed_increment(struct casinodev_device *dev, int si);

int exec(struct casinodev_device *dev, struct casinodev_cmd_feeder *feeder, int slot);


// chardev

int chardev_init(void);

void chardev_exit(void);

extern const struct file_operations casinodev_file_ops;

extern const struct file_operations casinodev_buffer_file_ops;


// tasks

int task_create_ioctl(struct casinodev_task **ret, struct casinodev_context *ctx, struct casinodev_ioctl_run r);

int task_create_write(struct casinodev_task **ret, struct casinodev_context *ctx,
        struct casinodev_buffer *buf, char* write_data, unsigned int len);

int task_execute(struct casinodev_task *t);

void task_destroy(struct casinodev_task *t);



#endif // CASINODRV_H