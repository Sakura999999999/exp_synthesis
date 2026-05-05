#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h> 
#include <linux/mutex.h>
#include <linux/ioctl.h>
#include <linux/version.h>
#include <linux/slab.h>

#define DEFECT_TYPE		"oob"
#define DEVICE_NAME		"uv_" DEFECT_TYPE "_dev"
#define CLASS_NAME		"uv_vul_cls"
#define VULOBJ_CACHE	"uv_" DEFECT_TYPE "_vulobj"

/* ioctl 的一系列定义，可自行修改 */
#define IOCTL_MAGIC		'Y'
#define IOCTL_ALLOC_VULOBJ		_IOWR(IOCTL_MAGIC, 0x01, int)
#define IOCTL_FREE_VULOBJ		_IOW(IOCTL_MAGIC, 0x02, int)
#define IOCTL_WRITE_VULOBJ		_IOW(IOCTL_MAGIC, 0x03, int)
#define IOCTL_READ_VICTIM		_IOR(IOCTL_MAGIC, 0x04, int)
#define IOCTL_EXECUTE_VICTIM	_IOW(IOCTL_MAGIC, 0x05, int)
#define IOCTL_ALLOC_VICTIM		_IOWR(IOCTL_MAGIC, 0x06, int)
#define IOCTL_FREE_VICTIM		_IOW(IOCTL_MAGIC, 0x07, int)
#define IOCTL_ALLOC_DUMMY 		_IOWR(IOCTL_MAGIC, 0x08, int)
#define IOCTL_FREE_DUMMY 		_IOW(IOCTL_MAGIC, 0x09, int)
#define IOCTL_GET_ADDR			_IOWR(IOCTL_MAGIC, 0x0A, struct addr_arg)
#define IOCTL_ALLOC_DEFRAG		_IOWR(IOCTL_MAGIC, 0x0B, int)

/* 对象类型定义，可自行修改 */
#define OBJ_TYPE_VUL		0
#define OBJ_TYPE_VICTIM		1
#define OBJ_TYPE_DUMMY		2
#define OBJ_TYPE_DEFRAG		3

#define DEFREG_MAX_SPRAY 	4096

#define HEAP_REAL 1 // 1表示开启真实堆环境

#define ARR_LENGTH 		512 

/* 漏洞对象大小，需自行修改 */
#define BUF_SIZE 		512 

/* vulobj, victim, dummy 可自行定义 */
typedef struct {
	char buffer[BUF_SIZE];
} uv_vulobj;

typedef struct {
	void (*funptr)(void);
    char buffer[BUF_SIZE - sizeof(void *)]; // set the size of victim_obj to 512
} uv_victim;

typedef struct {
	char buffer[BUF_SIZE];
} uv_dummy;

typedef struct {
	char buffer[BUF_SIZE];
} uv_defrag;

struct request_arg {
	int handler;
	int offset;
	char value;
};

struct addr_arg {
	int type;
	int handler;
	unsigned long addr;
};

static dev_t uv_devno;
static struct cdev uv_cdev;
static struct class *uv_class;
static struct device *uv_device;
static DEFINE_MUTEX(uv_lock);

static uv_vulobj *uv_vulobj_arr[ARR_LENGTH];
static int uv_vulobj_cnt;

static uv_victim *uv_victim_arr[ARR_LENGTH];
static int uv_victim_cnt;

static uv_dummy *uv_dummy_arr[ARR_LENGTH];
static int uv_dummy_cnt;

static uv_defrag *uv_defrag_arr[DEFREG_MAX_SPRAY];
static int uv_defrag_cnt;

/* 分配vulobj并将缓冲区填充为A(0x41) 
 * 可自行定义分配时的操作，下同 */
static uv_vulobj *uv_alloc_vulobj(size_t size) {
	uv_vulobj *obj = kmalloc(size, GFP_KERNEL);
    if (obj) {
        memset(obj->buffer, 'A', sizeof(obj->buffer));
    }
    return obj;
}

static void uv_free_vulobj(uv_vulobj *obj) {
	kfree(obj);
}

static uv_victim *uv_alloc_victim(size_t size) {
	uv_victim *obj = kmalloc(size, GFP_KERNEL);
    if (obj) {
        memset(obj->buffer, 'B', sizeof(obj->buffer));
    }
    return obj;
}

static void uv_free_victim(uv_victim *obj) {
	kfree(obj);
}

static uv_dummy *uv_alloc_dummy(size_t size) {
	uv_dummy *obj = kmalloc(size, GFP_KERNEL);
	if (obj) {
		memset(obj->buffer, 'C', sizeof(obj->buffer));
	}
	return obj;
}

static void uv_free_dummy(uv_dummy *obj) {
	kfree(obj);
}

static uv_defrag *uv_alloc_defrag(size_t size) {
	uv_defrag *obj = kmalloc(size, GFP_KERNEL);
	if (obj) {
		memset(obj->buffer, 'D', sizeof(obj->buffer));
	}
	return obj;
}

static int uv_open(struct inode *inode, struct file *file) {
	return 0;
}

static int uv_release(struct inode *inode, struct file *file) {
	return 0;
}

static void good_function(void) {
	printk(KERN_INFO "good\n");
}

static void bad_function(void) {
	printk(KERN_INFO "bad\n");
}

static long uv_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct request_arg req;
	struct addr_arg areq;
	void *obj;
	int handler;

	mutex_lock(&uv_lock);

    switch (cmd) {
		// 分配 vulobj
        case IOCTL_ALLOC_VULOBJ:
			handler = uv_vulobj_cnt;
			if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_vulobj_arr[uv_vulobj_cnt] = uv_alloc_vulobj(sizeof(uv_vulobj));
			if (uv_vulobj_arr[uv_vulobj_cnt]) {
				uv_vulobj_cnt++;
			}
			break;
        // 释放 vulobj
        case IOCTL_FREE_VULOBJ:
			if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_free_vulobj(uv_vulobj_arr[handler]);
			break;
		// 分配 victim
        case IOCTL_ALLOC_VICTIM:
			handler = uv_victim_cnt;
			if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_victim_arr[uv_victim_cnt] = uv_alloc_victim(sizeof(uv_victim));
			if (uv_victim_arr[uv_victim_cnt]) {
                uv_victim_arr[uv_victim_cnt]->funptr = good_function;
				uv_victim_cnt++;
			}
			break;
		// 释放 victim
        case IOCTL_FREE_VICTIM:
			if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_free_victim(uv_victim_arr[handler]);
			break;
		// 执行 victim 中的函数指针对应的函数
        case IOCTL_EXECUTE_VICTIM:
			if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			if (handler >= 0 && handler < uv_victim_cnt && uv_victim_arr[handler] != NULL) {
				if (uv_victim_arr[handler]->funptr) {
					uv_victim_arr[handler]->funptr();
				}
			}
			break;
		// 分配 dummy
		case IOCTL_ALLOC_DUMMY:
			handler = uv_dummy_cnt;
			if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_dummy_arr[uv_dummy_cnt] = uv_alloc_dummy(sizeof(uv_dummy));
			if (uv_dummy_arr[uv_dummy_cnt]) {
				uv_dummy_cnt++;
			}
			break;
		// 释放 dummy
		case IOCTL_FREE_DUMMY:
			if (copy_from_user(&handler, (void __user *)arg, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_free_dummy(uv_dummy_arr[handler]);
			break;
		// 去碎片化时分配 defrag 对象
		case IOCTL_ALLOC_DEFRAG:
			handler = uv_defrag_cnt;
			if (copy_to_user((void __user *)arg, &handler, sizeof(int))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			uv_defrag_arr[uv_defrag_cnt] = uv_alloc_defrag(sizeof(uv_defrag));
			if (uv_defrag_arr[uv_defrag_cnt]) {
				uv_defrag_cnt++;
			}
			break;
		// 写 vulobj
		case IOCTL_WRITE_VULOBJ:
			if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			if (req.handler >= 0 && req.handler < uv_vulobj_cnt && uv_vulobj_arr[req.handler] != NULL) {
                uv_vulobj_arr[req.handler]->buffer[req.offset] = req.value;
			}
			break;
		// 读 victim
        case IOCTL_READ_VICTIM:
			if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			if (req.handler >= 0 && req.handler < uv_victim_cnt && uv_victim_arr[req.handler] != NULL) {
				if (req.offset >= 0 && req.offset < (int)sizeof(uv_victim)) {
					req.value = ((char *)uv_victim_arr[req.handler])[req.offset];
					if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
						mutex_unlock(&uv_lock);
						return -EFAULT;
					}
				}
			}
            break;
		// 获取某个 obj[idx] 的地址
		case IOCTL_GET_ADDR:
			if (copy_from_user(&areq, (void __user *)arg, sizeof(areq))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			obj = NULL;
			// 根据 type 获取对应的 obj[idx]
			switch (areq.type) {
				case OBJ_TYPE_VUL:
					if (areq.handler >= 0 && areq.handler < uv_vulobj_cnt)
						obj = uv_vulobj_arr[areq.handler];
					break;
				case OBJ_TYPE_VICTIM:
					if (areq.handler >= 0 && areq.handler < uv_victim_cnt)
						obj = uv_victim_arr[areq.handler];
					break;
				case OBJ_TYPE_DUMMY:
					if (areq.handler >= 0 && areq.handler < uv_dummy_cnt)
						obj = uv_dummy_arr[areq.handler];
					break;
				case OBJ_TYPE_DEFRAG:
					if (areq.handler >= 0 && areq.handler < uv_defrag_cnt)
						obj = uv_defrag_arr[areq.handler];
					break;
				default:
					mutex_unlock(&uv_lock);
					return -EINVAL;
			}
			if (obj == NULL) {
				mutex_unlock(&uv_lock);
				return -EINVAL;
			}
			areq.addr = (unsigned long)obj;
			if (copy_to_user((void __user *)arg, &areq, sizeof(areq))) {
				mutex_unlock(&uv_lock);
				return -EFAULT;
			}
			break;
		 default:	
			break;
    }

    mutex_unlock(&uv_lock);

	return 0;
}

static const struct file_operations uv_fops = {
	.owner			= THIS_MODULE,
	.open			= uv_open,
	.release		= uv_release,
	.unlocked_ioctl	= uv_unlocked_ioctl,
};

static char *uv_devnode(struct device *dev, umode_t *mode) {
	if (mode)
		*mode = 0666;
	return NULL;
}

static int uv_init(void) {
	int ret;

	printk("[UV] good func: 0x%lx\n", (unsigned long)good_function);
	printk("[UV] bad func: 0x%lx\n", (unsigned long)bad_function);
	ret = alloc_chrdev_region(&uv_devno, 0, 1, DEVICE_NAME);
	if (ret) return ret;

	cdev_init(&uv_cdev, &uv_fops);
	uv_cdev.owner = THIS_MODULE;
	
	ret = cdev_add(&uv_cdev, uv_devno, 1);
	if (ret) goto err_unregister;
	
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
	uv_vulobj_cache = kmem_cache_create(VULOBJ_CACHE, sizeof(uv_vulobj_type), 0, 0, NULL);
#endif
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
	if (uv_vulobj_cache) kmem_cache_destroy(uv_vulobj_cache);
#endif
}

module_init(uv_init);
module_exit(uv_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("UV");
MODULE_DESCRIPTION("A simple module to test heap manipulations on an OOB vulnerability.");

