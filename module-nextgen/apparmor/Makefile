# Makefile for AppArmor Linux Security Module
#
# kernel build Makefile is the Kbuild file

KERNELVER := $(shell uname -r)

KERNELDIR := /lib/modules/${KERNELVER}/build

all:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules CONFIG_SECURITY_APPARMOR=m
	mv apparmor.ko apparmor-${KERNELVER}.ko
	mv match/aamatch_pcre.ko aamatch_pcre-${KERNELVER}.ko

clean:
	rm -f *~ *.o *.ko *.mod.c .*.cmd Modules.symvers \
		match/*~ match/*.o match/*.ko match/.*.cmd match/*.mod.c
	rm -rf .tmp_versions


