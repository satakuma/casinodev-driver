# casinodev-driver

Linux driver for the [casinodev](https://github.com/AndrzejJackowskiMIMUW/qemu/blob/casinodev/hw/misc/casinodev.c) PCI device.
Done as an assignment for Advanced Operating Systems course at University of Warsaw.

[Description (Polish)](https://students.mimuw.edu.pl/ZSO/PUBLIC-SO/2021-2022/z3_driver/index.html)

## Examples

```c
#include "casinodev.h"

#define SIZE 0x3000

int dev_create_buffer(int fd, int size, enum deck_type type) {
    struct casinodev_ioctl_create_decks cb = { size, type };
    int bfd;
    return ioctl(fd, CASINODEV_IOCTL_CREATE_DECKS, &cb);
}

int dev_run(int fd, int cmd_fd, uint32_t addr, uint32_t size, int buf_fd) {
    struct casinodev_ioctl_run run = {cmd_fd, addr, size, buf_fd};
    return ioctl(fd, CASINODEV_IOCTL_RUN, &run);
}

int dev_wait(int fd, uint32_t cnt) {
    struct casinodev_ioctl_wait wait = {cnt};
    return ioctl(fd, CASINODEV_IOCTL_WAIT, &wait);
}

int main() {
    int fd = open("/dev/casino0", O_RDWR);

    // Create a buffer for random cards.
    int buf_fd = dev_create_buffer(fd, SIZE, FULL);
    char *buffer = (char *) mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, buf_fd, 0);
    do_munmap(buffer + 0x2000, 0x1000);

    // casinodev command: generate 5 random cards with a fair distribution.
    uint32_t *cmd = (uint32_t*) (buffer + 0x1000);
    cmd[0] = CASINODEV_USER_CMD_GET_CARDS_HEADER(5, CASINODEV_USER_OUTPUT_FAIR);

    // Run the command and wait for completion.
    dev_run(fd, bfd, 0x1000, sizeof(uint32_t), bfd);
    dev_wait(fd, 0);

    // Use generated cards (for example in a casino).
    struct card * buf_read = (struct card *) buffer;
    for (int i = 0; i < 5; ++i) {
        use_card(buf_read[i].suit, buf_read[i].rank);
    }
}
```
