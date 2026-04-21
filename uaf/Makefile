# make KCFLAGS="-O1" VERSION=v5.10 ARCH=i386

# obj-m := uaf1.o
# obj-m += uaf2.o
# obj-m += uaf3.o
# obj-m+= uaf4.o
obj-m+= uaf5.o

CURRENT_PATH := $(shell pwd)
KERNEL_PATH := $(HOME)/Kernel/v6.6/x86_64

all:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(KERNEL_PATH) M=$(CURRENT_PATH) clean
