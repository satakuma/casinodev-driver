#include <linux/module.h>
#include <linux/kernel.h>

#include "casinodrv.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("casinodev driver");

static int casinodev_init(void) {
    int err;
    pr_info(CASINODRV_PREF "Loading casinodev driver\n");
    if ((err = pcidev_init()))
        goto err_pcidev;
    if ((err = chardev_init()))
        goto err_chardev;

    return 0;

err_chardev:
    pcidev_exit();
err_pcidev:
    pr_warn(CASINODRV_PREF "Failed to load casinodev driver\n");
    return err;
}

static void casinodev_exit(void) {
    pr_info(CASINODRV_PREF "Unloading casinodev driver\n");
    pcidev_exit();
    chardev_exit();
}

module_init(casinodev_init);
module_exit(casinodev_exit);
