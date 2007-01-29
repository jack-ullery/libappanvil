KERNELVER := $(shell uname -r)
KERNELDIR := /lib/modules/${KERNELVER}/build

all:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules  CONFIG_SECURITY_FOOBAR=m
