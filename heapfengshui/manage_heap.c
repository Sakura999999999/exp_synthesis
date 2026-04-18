#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define IOCTL_MAGIC     'Y'
#define IOCTL_ALLOC_VULOBJ      _IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULOBJ       _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_ALLOC_VICTIM      _IOWR(IOCTL_MAGIC, 0x07, int)
#define IOCTL_FREE_VICTIM       _IOW(IOCTL_MAGIC, 0x08, int)
#define IOCTL_ALLOC_DUMMY 		_IOWR(IOCTL_MAGIC, 0x09, int)
#define IOCTL_FREE_DUMMY 		_IOW(IOCTL_MAGIC, 0x0A, int)

// void print_usage(char *name) {
//     printf("Usage:\n");
//     printf("  %s alloc_vul <count>     - 批量分配 vulobj\n", name);
//     printf("  %s free_vul <idx>        - 释放指定的 vulobj\n", name);
//     printf("  %s alloc_vic <count>     - 批量分配 victim\n", name);
//     printf("  %s free_vic <idx>        - 释放指定的 victim\n", name);
// }

int main(int argc, char *argv[]) {
    // if (argc < 3) {
    //     print_usage(argv[0]);
    //     return -1;
    // }

    int fd = open("/dev/uv_oob_dev", O_RDWR);
    if (fd < 0) {
        perror("[-] Open device failed");
        return -1;
    }

    char *cmd = argv[1];
    int val = atoi(argv[2]);

    if (strcmp(cmd, "alloc_vul") == 0) {
        for (int i = 0; i < val; i++) {
            int handler = 0;
            if (ioctl(fd, IOCTL_ALLOC_VULOBJ, &handler) == 0)
                printf("[+] [%d/%d] Allocated VULOBJ, index: %d\n", i + 1, val, handler);
            else
                perror("[-] Alloc VULOBJ failed");
        }
    } 
    else if (strcmp(cmd, "free_vul") == 0) {
        if (ioctl(fd, IOCTL_FREE_VULOBJ, &val) == 0)
            printf("[+] Freed VULOBJ index: %d\n", val);
        else
            perror("[-] Free VULOBJ failed");
    } 
    else if (strcmp(cmd, "alloc_vic") == 0) {
        for (int i = 0; i < val; i++) {
            int handler = 0;
            if (ioctl(fd, IOCTL_ALLOC_VICTIM, &handler) == 0)
                printf("[+] [%d/%d] Allocated VICTIM, index: %d\n", i + 1, val, handler);
            else
                perror("[-] Alloc VICTIM failed");
        }
    } 
    else if (strcmp(cmd, "free_vic") == 0) {
        if (ioctl(fd, IOCTL_FREE_VICTIM, &val) == 0)
            printf("[+] Freed VICTIM index: %d\n", val);
        else
            perror("[-] Free VICTIM failed");
    } 
    else if (strcmp(cmd, "alloc_dmy") == 0) {
        for (int i = 0; i < val; i++) {
            int handler = 0;
            if (ioctl(fd, IOCTL_ALLOC_DUMMY, &handler) == 0)
                printf("[+] [%d/%d] Allocated DUMMY, index: %d\n", i + 1, val, handler);
            else
                perror("[-] Alloc DUMMY failed");
        }
    } 
    else if (strcmp(cmd, "free_dmy") == 0) {
        if (ioctl(fd, IOCTL_FREE_DUMMY, &val) == 0)
            printf("[+] Freed DUMMY index: %d\n", val);
        else
            perror("[-] Free DUMMY failed");
    }
    else {
        // print_usage(argv[0]);
    }

    close(fd);
    return 0;
}