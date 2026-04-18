obj-m := oob_heapfengshui.o

EXTRA_CFLAGS += -g -O0

CURRENT_PATH := $(shell pwd)
# 你需要根据实际环境修改内核路径
KERNEL_PATH ?= $(HOME)/Kernel/v5.13/x86_64

all:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) clean
