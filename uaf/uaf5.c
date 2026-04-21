#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define DEBUG
#define DEFECT_TYPE "uaf"
#define DEVICE_NAME "uv_" DEFECT_TYPE "_dev"
#define CLASS_NAME "uv_vul_cls"
#define VULOBJ_CACHE "uv_" DEFECT_TYPE "_vulobj"
#define IOCTL_MAGIC 'X'
#define ARR_LENGTH 8192
#define BUF_SIZE 512

// =========================================================================
// [1] Vulobj (漏洞实体) 及其 API 定义
// =========================================================================
typedef struct {
  char buffer[BUF_SIZE];
} uv_vulobj_t;

#define IOCTL_VUL_ALLOC _IOR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_VUL_FREE _IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_VUL_WRITE _IOW(IOCTL_MAGIC, 0x03, struct uv_req)

// =========================================================================
// [2] Vicobj (受害实体) 及其 API 定义
// =========================================================================
typedef struct {
  unsigned long *next;
  unsigned long *prev;
  char buffer[BUF_SIZE - 16];
} uv_vic_unlink_t;

#define IOCTL_VIC_UNL_ALLOC _IOR(IOCTL_MAGIC, 0x10, int)
#define IOCTL_VIC_UNL_TRIG _IOW(IOCTL_MAGIC, 0x11, int)

// =========================================================================
// [3] 辅助 API 定义
// =========================================================================
#define IOCTL_LEAK _IOR(IOCTL_MAGIC, 0x20, struct uv_leak)
#define IOCTL_CHECK _IO(IOCTL_MAGIC, 0x21)

struct uv_req {
  int handler;
  int offset;
  unsigned long value;
};
struct uv_leak {
  unsigned long target_addr;
  unsigned long sink_addr;
};

static dev_t uv_devno;
static struct cdev uv_cdev;
static struct class *uv_class;
static struct device *uv_device;
static DEFINE_MUTEX(uv_lock);

static struct kmem_cache *uv_vulobj_cache;

// --- 核心修改：将漏洞对象和受害对象的句柄池物理隔离 ---
static void *uv_vul_arr[ARR_LENGTH];
static int uv_vul_cnt;

static void *uv_vic_arr[ARR_LENGTH];
static int uv_vic_cnt;

char uv_target_string[256] = "/sbin/modprobe";
char uv_physmap_dummy[4096] = {0};

static int uv_open(struct inode *inode, struct file *file) { return 0; }
static int uv_release(struct inode *inode, struct file *file) { return 0; }

static long uv_unlocked_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg) {
  int handler;
  struct uv_req req;
  struct uv_leak leak;

  mutex_lock(&uv_lock);

  switch (cmd) {
  // --- Vulobj APIs ---
  case IOCTL_VUL_ALLOC:
    handler = uv_vul_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int)))
      goto fault;
    uv_vul_arr[uv_vul_cnt++] = kmem_cache_alloc(uv_vulobj_cache, GFP_KERNEL);
    break;

  case IOCTL_VUL_FREE:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int)))
      goto fault;
    if (handler >= 0 && handler < uv_vul_cnt && uv_vul_arr[handler]) {
      kmem_cache_free(uv_vulobj_cache, uv_vul_arr[handler]);
      // 故意不置空 uv_vul_arr[handler]，保留悬垂指针以触发 UAF
    }
    break;

  case IOCTL_VUL_WRITE:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
      goto fault;
    // --- 核心修改：修复 OOB 漏洞，收紧偏移量检查 ---
    if (req.handler >= 0 && req.handler < uv_vul_cnt &&
        uv_vul_arr[req.handler] &&
        req.offset <= BUF_SIZE - sizeof(unsigned long)) {
      *(unsigned long *)((char *)uv_vul_arr[req.handler] + req.offset) =
          req.value;
    }
    break;

  // --- Vicobj APIs ---
  case IOCTL_VIC_UNL_ALLOC:
    handler = uv_vic_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int)))
      goto fault;
    // 使用同一个 cache，保证和 vulobj 能够发生物理重叠
    uv_vic_arr[uv_vic_cnt++] = kmem_cache_alloc(uv_vulobj_cache, GFP_KERNEL);
    break;

  case IOCTL_VIC_UNL_TRIG:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int)))
      goto fault;
    if (handler >= 0 && handler < uv_vic_cnt && uv_vic_arr[handler]) {
      uv_vic_unlink_t *vic = (uv_vic_unlink_t *)uv_vic_arr[handler];
      unsigned long next = (unsigned long)vic->next;
      unsigned long prev = (unsigned long)vic->prev;
      if (next && prev) {
        *(unsigned long *)(next + 8) = prev;
        *(unsigned long *)(prev + 0) = next;
      }
    }
    break;

  // --- 辅助 APIs ---
  case IOCTL_LEAK:
    leak.target_addr = (unsigned long)uv_target_string;
    leak.sink_addr = (unsigned long)uv_physmap_dummy;
    if (copy_to_user((void __user *)arg, &leak, sizeof(leak)))
      goto fault;
    break;

  case IOCTL_CHECK:
    pr_info("[UV] Verification: Target is now: '%s'\n", uv_target_string);
    break;

  default:
    mutex_unlock(&uv_lock);
    return -ENOTTY;
  }

  mutex_unlock(&uv_lock);
  return 0;

fault:
  mutex_unlock(&uv_lock);
  return -EFAULT;
}

static const struct file_operations uv_fops = {
    .owner = THIS_MODULE,
    .open = uv_open,
    .release = uv_release,
    .unlocked_ioctl = uv_unlocked_ioctl,
};

static int uv_init(void) {
  int ret = alloc_chrdev_region(&uv_devno, 0, 1, DEVICE_NAME);
  if (ret)
    return ret;
  cdev_init(&uv_cdev, &uv_fops);
  uv_cdev.owner = THIS_MODULE;
  ret = cdev_add(&uv_cdev, uv_devno, 1);
  if (ret)
    goto err_unregister;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
  uv_class = class_create(THIS_MODULE, CLASS_NAME);
#else
  uv_class = class_create(CLASS_NAME);
#endif
  if (IS_ERR(uv_class)) {
    ret = PTR_ERR(uv_class);
    goto err_cdev_del;
  }
  uv_device = device_create(uv_class, NULL, uv_devno, NULL, DEVICE_NAME);
  if (IS_ERR(uv_device)) {
    ret = PTR_ERR(uv_device);
    goto err_class_destroy;
  }

  uv_vulobj_cache = kmem_cache_create(VULOBJ_CACHE, BUF_SIZE, 0, 0, NULL);
  return 0;

err_class_destroy:
  class_destroy(uv_class);
err_cdev_del:
  cdev_del(&uv_cdev);
err_unregister:
  unregister_chrdev_region(uv_devno, 1);
  return ret;
}

static void uv_exit(void) {
  device_destroy(uv_class, uv_devno);
  class_destroy(uv_class);
  cdev_del(&uv_cdev);
  unregister_chrdev_region(uv_devno, 1);
  if (uv_vulobj_cache)
    kmem_cache_destroy(uv_vulobj_cache);
}

module_init(uv_init);
module_exit(uv_exit);
MODULE_LICENSE("Dual BSD/GPL");