#include <linux/uaccess.h>
#include <asm/set_memory.h>

#include "casinodrv.h"

#define PALIGNMENT     (1 << 12)
#define MK_PTE(daddr) (((daddr) >> 8) | 0x1)
// [0] bit: PRESENT bit, [4..31] bits: [12..39] bits of the physical addr


static inline int get_num_pages(size_t size) {
    return (size + CASINODEV_PAGE_SIZE - 1) / CASINODEV_PAGE_SIZE;
}

static inline void *dma_zalloc_page(struct device *dev, dma_addr_t *dma_handle) {
    return dma_alloc_coherent(dev, CASINODEV_PAGE_SIZE, dma_handle, GFP_KERNEL | __GFP_ZERO);
}

static inline void dma_free_page(struct device *dev, void* cpu_addr, dma_addr_t dma_handle) {
    dma_free_coherent(dev, CASINODEV_PAGE_SIZE, cpu_addr, dma_handle);
}


int alloc_casinodev_pt(struct casinodev_pt *pt, struct casinodev_device *dev, size_t size) {
    int i, err;

    int num_pages = get_num_pages(size);

    // Allocate page for the page table
    if (!(pt->pt.kern = dma_zalloc_page(&dev->pdev->dev, &pt->pt.dev))) {
        err = -ENOMEM;
        goto alloc_pt;
    }

    // Allocate array of page handles
    if (!(pt->pages = kzalloc(sizeof(struct casinodev_page) * num_pages, GFP_KERNEL))) {
        err = -ENOMEM;
        goto alloc_pages;
    }

    // Allocate dma memory for pages
    for (i = 0; i < num_pages; i++) {
        if (!(pt->pages[i].kern = dma_zalloc_page(&dev->pdev->dev, &pt->pages[i].dev))) {
            err = -ENOMEM;
            goto alloc_page;
        }
        BUG_ON(pt->pages[i].dev & (PALIGNMENT - 1));
        ((uint32_t*) pt->pt.kern)[i] = MK_PTE(pt->pages[i].dev);
    }

    pt->num_pages = num_pages;
    return 0;

alloc_page:
    for (i = 0; i < num_pages; i++) {
        if (pt->pages[i].kern) {
            dma_free_page(&dev->pdev->dev, pt->pages[i].kern, pt->pages[i].dev);
        } else {
            break;
        }
    }
    kfree(pt->pages);
alloc_pages:
    dma_free_page(&dev->pdev->dev, pt->pt.kern, pt->pt.dev);
alloc_pt:
    return err;
}


void free_casinodev_pt(struct casinodev_pt *pt, struct casinodev_device *dev) {
    int i;
    for (i = 0; i < pt->num_pages; i++) {
        if (pt->pages[i].kern) {
            dma_free_page(&dev->pdev->dev, pt->pages[i].kern, pt->pages[i].dev);
        } else {
            break;
        }
    }
    kfree(pt->pages);
    dma_free_page(&dev->pdev->dev, pt->pt.kern, pt->pt.dev);
}