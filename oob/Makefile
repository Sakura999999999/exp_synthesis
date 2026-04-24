obj-m := oob.o

CURRENT_PATH := $(shell pwd)
# 你需要根据实际环境修改内核路径
KERNEL_PATH ?= $(HOME)/Kernel/v7.0/x86_64

all:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) clean
