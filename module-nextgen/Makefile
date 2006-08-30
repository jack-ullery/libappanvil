# Makefile for AppArmor Linux Security Module (previously called "SubDomain")
#
# kernel build Makefile is the Kbuild file

REPO_VERSION := $(shell if [ -x /usr/bin/svn ] ; then \
	/usr/bin/svn info . 2> /dev/null | grep "^Last Changed Rev:" | sed "s/^Last Changed Rev: //" ; \
	fi)

ifeq ("${REPO_VERSION}", "")
REPO_VERSION := "unknown"
endif

KERNELVER := $(shell uname -r)

KERNELDIR := /lib/modules/${KERNELVER}/build

all:
	$(MAKE) -C $(KERNELDIR) M=`pwd` APPARMOR_VER=${REPO_VERSION} $@
	mv apparmor.ko apparmor-${KERNELVER}.ko
	mv aamatch/aamatch_pcre.ko aamatch_pcre-${KERNELVER}.ko

clean:
	rm -f *.o *.ko *.mod.c .*.cmd Modules.symvers \
		aamatch/*.o aamatch/*.ko aamatch/.*.cmd aamatch/*.mod.c
	rm -rf .tmp_versions
