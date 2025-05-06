#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <errno.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s /dev/i2c-X\n", argv[0]);
        return 1;
    }
    const char *dev = argv[1];
    int fd = open(dev, O_RDWR);
    if (fd < 0)
    {
        perror("open");
        return 1;
    }
    printf("Scanning %s:\n", dev);
    for (int addr = 0x03; addr < 0x78; addr++)
    {
        if (ioctl(fd, I2C_SLAVE, addr) < 0)
            continue;
        // try a quick read
        unsigned char buf;
        if (read(fd, &buf, 1) == 1)
            printf("  found device at 0x%02x\n", addr);
    }
    close(fd);
    return 0;
}
