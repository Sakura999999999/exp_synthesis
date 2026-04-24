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

#define DEFECT_TYPE "oob"
#define DEVICE_NAME "uv_" DEFECT_TYPE "_dev"
#define CLASS_NAME "uv_vul_cls"
#define BRIDGE_CACHE "uv_" DEFECT_TYPE "_bridge"
#define ROUTER_CACHE "uv_" DEFECT_TYPE "_router"
#define TARGET_CACHE "uv_" DEFECT_TYPE "_target"

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

#define ARR_LENGTH 512
#define BUF_SIZE 512

typedef struct {
  char buffer[BUF_SIZE + sizeof(void *)];
} uv_vuln;

typedef struct {
  int offset;
  int length;
  char buffer[BUF_SIZE];
} uv_elas;

typedef struct {
  void (*funp)(void);
  char buffer[BUF_SIZE];
} uv_victim;

typedef struct {
  int length;
  void *destptr;
  char buffer[BUF_SIZE - 8];
} bridge;

typedef struct {
  char buffer[BUF_SIZE];
} destbuf;

typedef struct {
  void *targetptr;
  char buffer[BUF_SIZE - 8];
} router;

typedef struct {
  char buffer[32];
} target;

struct request_arg {
  int handler;
  int offset;
  int length;
  char *value;
};

static dev_t uv_devno;
static struct cdev uv_cdev;
static struct class *uv_class;
static struct device *uv_device;
static DEFINE_MUTEX(uv_lock);

// #define HEAP_REAL 1

static struct kmem_cache *uv_cache1;
static struct kmem_cache *uv_cache2;
static struct kmem_cache *uv_cache3;
static uv_vuln *uv_vuln_arr[ARR_LENGTH];
static int uv_vuln_cnt;
static uv_elas *uv_elas_arr[ARR_LENGTH];
static int uv_elas_cnt;
static uv_victim *uv_victim_arr[ARR_LENGTH];
static int uv_victim_cnt;
static bridge *uv_bridge_arr[ARR_LENGTH];
static int uv_bridge_cnt;
static router *uv_router_arr[ARR_LENGTH];
static int uv_router_cnt;

static target *targetptr;
static uv_victim *victimptr;

static uv_vuln *uv_alloc_vuln(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache1, GFP_KERNEL);
#endif
}

static void uv_free_vuln(uv_vuln *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache1, obj);
#endif
}

static uv_elas *uv_alloc_elas(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache1, GFP_KERNEL);
#endif
}

static void uv_free_elas(uv_elas *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache1, obj);
#endif
}

static uv_victim *uv_alloc_victim(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache1, GFP_KERNEL);
#endif
}

static void uv_free_victim(uv_victim *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache1, obj);
#endif
}

static bridge *uv_alloc_bridge(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache1, GFP_KERNEL);
#endif
}

static void uv_free_bridge(bridge *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache1, obj);
#endif
}

static destbuf *uv_alloc_destbuf(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache2, GFP_KERNEL);
#endif
}

static void uv_free_destbuf(destbuf *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache2, obj);
#endif
}

static router *uv_alloc_router(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache2, GFP_KERNEL);
#endif
}

static void uv_free_router(router *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache2, obj);
#endif
}

static target *uv_alloc_target(size_t size) {
#ifdef HEAP_REAL
  return kmalloc(size, GFP_KERNEL);
#else
  return kmem_cache_alloc(uv_cache3, GFP_KERNEL);
#endif
}

static void uv_free_target(target *obj) {
#ifdef HEAP_REAL
  kfree(obj);
#else
  if (obj)
    kmem_cache_free(uv_cache3, obj);
#endif
}

static int uv_open(struct inode *inode, struct file *file) { return 0; }

static int uv_release(struct inode *inode, struct file *file) { return 0; }

static void good_function(void) { printk(KERN_INFO "good\n"); }

static void bad_function(void) { printk(KERN_INFO "bad\n"); }

static long uv_unlocked_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg) {
  struct request_arg req;
  int handler;

  mutex_lock(&uv_lock);

  switch (cmd) {
  case IOCTL_ALLOC_VULN:
    handler = uv_vuln_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_vuln_arr[uv_vuln_cnt] = uv_alloc_vuln(sizeof(uv_vuln));
    if (uv_vuln_arr[uv_vuln_cnt]) {
      printk(KERN_INFO "[UV] vuln[%d] @ %px\n", handler,
             uv_vuln_arr[uv_vuln_cnt]);
      uv_vuln_cnt++;
    }
    break;
  case IOCTL_FREE_VULN:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_free_vuln(uv_vuln_arr[handler]);
    break;
  case IOCTL_WRITE_VULN:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_vuln_cnt &&
        uv_vuln_arr[req.handler] != NULL) {
      memcpy(uv_vuln_arr[req.handler]->buffer + req.offset, req.value,
             req.length);
    }
    break;
  case IOCTL_READ_VULN:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_vuln_cnt &&
        uv_vuln_arr[req.handler] != NULL) {
      memcpy(req.value, uv_vuln_arr[req.handler]->buffer + req.offset,
             req.length);
      if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
        mutex_unlock(&uv_lock);
        return -EFAULT;
      }
    }
    break;
  case IOCTL_ALLOC_ELS:
    handler = uv_elas_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_elas_arr[uv_elas_cnt] = uv_alloc_elas(sizeof(uv_elas));
    if (uv_elas_arr[uv_elas_cnt]) {
      uv_elas_arr[uv_elas_cnt]->offset = 0;
      uv_elas_arr[uv_elas_cnt]->length = 0;
      printk(KERN_INFO "[UV] els[%d] @ %px\n", handler,
             uv_elas_arr[uv_elas_cnt]);
      printk(KERN_INFO "[UV] els[%d] offset @ %px length @ %px buffer @ %px\n",
             handler, &uv_elas_arr[uv_elas_cnt]->offset,
             &uv_elas_arr[uv_elas_cnt]->length,
             uv_elas_arr[uv_elas_cnt]->buffer);
      uv_elas_cnt++;
    }
    break;
  case IOCTL_FREE_ELS:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_free_elas(uv_elas_arr[handler]);
    break;
  case IOCTL_WRITE_ELS:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_elas_cnt &&
        uv_elas_arr[req.handler] != NULL) {
      memcpy((uv_elas_arr[req.handler])->buffer + req.offset, req.value,
             req.length);
    }
    break;
  case IOCTL_READ_ELS:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_elas_cnt &&
        uv_elas_arr[req.handler] != NULL) {
      memcpy(req.value,
             (uv_elas_arr[req.handler])->buffer +
                 uv_elas_arr[req.handler]->offset,
             uv_elas_arr[req.handler]->length);
      req.length = uv_elas_arr[req.handler]->length;
      if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
        mutex_unlock(&uv_lock);
        return -EFAULT;
      }
    }
    break;
  case IOCTL_ALLOC_VICTIM:
    handler = uv_victim_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_victim_arr[uv_victim_cnt] = uv_alloc_victim(sizeof(uv_victim));
    if (uv_victim_arr[uv_victim_cnt]) {
      (uv_victim_arr[uv_victim_cnt])->funp = good_function;
      printk(KERN_INFO "[UV] victim[%d] @ %px funp=%px\n", handler,
             uv_victim_arr[uv_victim_cnt], uv_victim_arr[uv_victim_cnt]->funp);
      uv_victim_cnt++;
    }
    break;
  case IOCTL_FREE_VICTIM:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_free_victim(uv_victim_arr[handler]);
    break;
  case IOCTL_WRITE_VICTIM:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_victim_cnt &&
        uv_victim_arr[req.handler] != NULL) {
      memcpy((uv_victim_arr[req.handler])->buffer + req.offset, req.value,
             req.length);
    }
    break;
  case IOCTL_READ_VICTIM:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_victim_cnt &&
        uv_victim_arr[req.handler] != NULL) {
      memcpy(req.value, (uv_victim_arr[req.handler])->buffer + req.offset,
             req.length);
      if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
        mutex_unlock(&uv_lock);
        return -EFAULT;
      }
    }
    break;
  case IOCTL_EXECUTE_VICTIM:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (handler >= 0 && handler < uv_victim_cnt &&
        uv_victim_arr[handler] != NULL) {
      if (uv_victim_arr[handler]->funp) {
        uv_victim_arr[handler]->funp();
      }
    }
    break;
  case IOCTL_ALLOC_BRIDGE:
    handler = uv_bridge_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_bridge_arr[uv_bridge_cnt] = uv_alloc_bridge(sizeof(bridge));
    uv_bridge_arr[uv_bridge_cnt]->destptr = uv_alloc_destbuf(sizeof(destbuf));
    if (uv_bridge_arr[uv_bridge_cnt]) {
      printk(KERN_INFO "[UV] bridge[%d] @ %px\n", handler,
             uv_bridge_arr[uv_bridge_cnt]);
      printk(KERN_INFO "[UV] bridge[%d] destptr @ %px\n", handler,
             uv_bridge_arr[uv_bridge_cnt]->destptr);
      printk(KERN_INFO "[UV] bridge[%d] length @ %px\n", handler,
             &uv_bridge_arr[uv_bridge_cnt]->length);
      printk(KERN_INFO "[UV] bridge[%d] buffer @ %px\n", handler,
             uv_bridge_arr[uv_bridge_cnt]->buffer);
      uv_bridge_cnt++;
    }
    break;
  case IOCTL_FREE_BRIDGE:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_free_bridge(uv_bridge_arr[handler]);
    uv_free_destbuf(uv_bridge_arr[handler]->destptr);
    break;
  case IOCTL_COPY_BRIDGE:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (handler >= 0 && handler < uv_bridge_cnt &&
        uv_bridge_arr[handler] != NULL) {
      memcpy((uv_bridge_arr[handler])->destptr,
             (uv_bridge_arr[handler])->buffer, uv_bridge_arr[handler]->length);
    }
    break;
  case IOCTL_WRITE_ROUTER:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_router_cnt &&
        uv_router_arr[req.handler] != NULL) {
      memcpy((uv_router_arr[req.handler])->buffer + req.offset, req.value,
             req.length);
    }
    break;
  case IOCTL_READ_ROUTER:
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (req.handler >= 0 && req.handler < uv_router_cnt &&
        uv_router_arr[req.handler] != NULL) {
      memcpy(req.value, (uv_router_arr[req.handler])->buffer + req.offset,
             req.length);
      if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
        mutex_unlock(&uv_lock);
        return -EFAULT;
      }
    }
    break;
  case IOCTL_ALLOC_ROUTER:
    handler = uv_router_cnt;
    if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_router_arr[uv_router_cnt] = uv_alloc_router(sizeof(router));
    uv_router_arr[uv_router_cnt]->targetptr = uv_alloc_target(sizeof(target));
    if (uv_router_arr[uv_router_cnt]) {
      printk(KERN_INFO "[UV] router[%d] @ %px\n", handler,
             uv_router_arr[uv_router_cnt]);
      printk(KERN_INFO "[UV] router[%d] targetptr @ %px\n", handler,
             uv_router_arr[uv_router_cnt]->targetptr);
      printk(KERN_INFO "[UV] router[%d] buffer @ %px\n", handler,
             uv_router_arr[uv_router_cnt]->buffer);
      uv_router_cnt++;
    }
    break;
  case IOCTL_FREE_ROUTER:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    uv_free_router(uv_router_arr[handler]);
    uv_free_target(uv_router_arr[handler]->targetptr);
    break;
  case IOCTL_COPY_ROUTER:
    if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
      mutex_unlock(&uv_lock);
      return -EFAULT;
    }
    if (handler >= 0 && handler < uv_router_cnt &&
        uv_router_arr[handler] != NULL) {
      char dummy[] = "deadbeef";
      memcpy((uv_router_arr[handler])->targetptr, dummy, sizeof(dummy));
    }
    break;
  case IOCTL_SHOW_TARGET:
    printk(KERN_INFO "[UV] targetptr: %s\n", targetptr->buffer);
    break;
  }

  mutex_unlock(&uv_lock);

  return 0;
}

static const struct file_operations uv_fops = {
    .owner = THIS_MODULE,
    .open = uv_open,
    .release = uv_release,
    .unlocked_ioctl = uv_unlocked_ioctl,
};

static char *uv_devnode(const struct device *dev, umode_t *mode) {
  if (mode)
    *mode = 0666;
  return NULL;
}

static int uv_init(void) {
  int ret;

  printk("[UV] good func: 0x%lx\n", (unsigned long)good_function);
  printk("[UV] bad func: 0x%lx\n", (unsigned long)bad_function);
  ret = alloc_chrdev_region(&uv_devno, 0, 1, DEVICE_NAME);
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

  uv_class->devnode = uv_devnode;

  uv_device = device_create(uv_class, NULL, uv_devno, NULL, DEVICE_NAME);
  if (IS_ERR(uv_device)) {
    ret = PTR_ERR(uv_device);
    goto err_class_destroy;
  }

#ifndef HEAP_REAL
  uv_cache1 = kmem_cache_create(BRIDGE_CACHE, sizeof(uv_vuln), 0, 0, NULL);
  uv_cache2 = kmem_cache_create(ROUTER_CACHE, sizeof(router), 0, 0, NULL);
  uv_cache3 = kmem_cache_create(TARGET_CACHE, sizeof(target), 0, 0, NULL);
#endif
  // targetptr = uv_alloc_target(sizeof(target));
  // memcpy(targetptr->buffer, "failed", sizeof("failed"));
  // printk(KERN_INFO "[UV] targetptr: 0x%lx\n", (unsigned long)targetptr);
  victimptr = uv_alloc_victim(sizeof(uv_victim));
  memcpy(victimptr->buffer, "victim", sizeof("victim"));
  printk(KERN_INFO "[UV] victimptr: 0x%lx\n", (unsigned long)victimptr);
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

#ifndef HEAP_REAL
  if (uv_cache1)
    kmem_cache_destroy(uv_cache1);
  if (uv_cache2)
    kmem_cache_destroy(uv_cache2);
  if (uv_cache3)
    kmem_cache_destroy(uv_cache3);
#endif
}

module_init(uv_init);
module_exit(uv_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("UV");
MODULE_DESCRIPTION("A simple module to simulate an OOB vulnerability.");
