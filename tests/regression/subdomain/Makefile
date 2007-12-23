# $Id$
#
#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

SRC=access.c \
    changehat.c \
    changehat_fork.c \
    changehat_misc.c \
    changehat_misc2.c \
    changehat_twice.c \
    changehat_fail.c \
    changehat_wrapper.c \
    changehat_pthread.c \
    chdir.c \
    chgrp.c \
    chmod.c \
    chown.c \
    clone.c \
    deleted.c \
    environ.c \
    env_check.c \
    exec.c \
    exec_qual.c \
    exec_qual2.c \
    fchdir.c \
    fchgrp.c \
    fchmod.c \
    fchown.c \
    fork.c \
    link.c \
    link_subset.c \
    mmap.c \
    mkdir.c \
    mount.c \
    named_pipe.c \
    net_raw.c \
    open.c \
    openat.c \
    pipe.c \
    ptrace.c \
    ptrace_helper.c \
    pwrite.c \
    rename.c \
    readdir.c \
    rw.c \
    symlink.c \
    syscall_mknod.c \
    swap.c \
    syscall_chroot.c \
    syscall_mlockall.c \
    syscall_ptrace.c \
    syscall_reboot.c \
    syscall_setpriority.c \
    syscall_sethostname.c \
    syscall_setdomainname.c \
    syscall_setscheduler.c \
    syscall_sysctl.c \
    sysctl_proc.c \
    tcp.c \
    unix_fd_client.c \
    unix_fd_server.c \
    unlink.c \
    xattrs.c

#only do the ioperm/iopl tests for x86 derived architectures
ifneq (,$(findstring $(shell uname -i),i386 i486 i586 i686 x86 x86_64))
SRC+=syscall_ioperm.c syscall_iopl.c
endif

# Suck, Fedora Core 3 no longer includes /sbin/kernelversion
KERNELVERSION:=$(shell if [ -x /sbin/kernelversion ] ; then \
				/sbin/kernelversion ; \
		       else \
		       		uname -r ; \
		       fi )
KERNELMAJOR:=$(shell echo ${KERNELVERSION} | cut -d. -f1)
KERNELMINOR:=$(shell echo ${KERNELVERSION} | cut -d. -f2)
CHANGEHAT_FLAGS=$(shell if [ ! -f /usr/include/sys/apparmor.h ] ; then \
        			if [ -f /usr/include/sys/immunix.h ] ; then \
					echo -DUSE_COMPAT_IMMUNIX_H ; \
				else \
					(echo -DCHANGEHAT_NOT_IN_LIBRARY; \
					[ $(KERNELMAJOR) -eq 2 ] && \
	  				if [ $(KERNELMINOR) -eq 4 ] ; then \
						echo -DCHANGEHAT_2_4_KERNEL ; \
	  				elif [ $(KERNELMINOR) -eq 2 ] ; then \
						echo -DCHANGEHAT_2_2_KERNEL ;\
	       				fi ) \
	  			fi ;\
			fi )

LIBIMMUNIX:=$(shell	if [ -f /usr/lib/libapparmor.so -o -f /usr/lib64/libapparmor.so ] ; then \
				echo -lapparmor ; \
			elif [ -f /lib/libimmunix.so.1 -o -f /lib64/libimmunix.so ] ; then \
				echo -limmunix ; \
			fi )

CFLAGS+=$(CHANGEHAT_FLAGS) $(LIBIMMUNIX) -Wall -Wstrict-prototypes

EXEC=$(SRC:%.c=%)

TESTS=access \
      capabilities \
      changehat \
      changehat_fork \
      changehat_misc \
      chdir \
      clone \
      deleted \
      environ \
      exec \
      exec_qual \
      fchdir \
      fork \
      i18n \
      link \
      link_subset \
      mkdir \
      mmap \
      mount \
      mult_mount \
      named_pipe \
      net_raw \
      open \
      openat \
      pipe \
      ptrace \
      pwrite \
      regex \
      rename \
      readdir \
      rw \
      swap \
      sd_flags \
      setattr \
      symlink \
      syscall \
      unix_fd_server \
      unlink\
      xattrs

# Tests that can crash the kernel should be placed here
RISKY_TESTS=longpath

all: $(EXEC) changehat.h

changehat_pthread: changehat_pthread.c changehat.h
	${CC} ${CFLAGS} -lpthread -o $@ $<

tests: all
	@if [ `whoami` = "root" ] ;\
	then \
		for i in $(TESTS) ;\
		do \
			echo ;\
			echo "running $$i" ;\
			bash $$i.sh ;\
		done ;\
	else \
		echo "must be root to run tests" ;\
	fi

alltests: all
	@if [ `whoami` = "root" ] ;\
	then \
		for i in $(TESTS) $(RISKY_TESTS) ;\
		do \
			echo ;\
			echo "running $$i" ;\
			bash $$i.sh ;\
		done ;\
	else \
		echo "must be root to run tests" ;\
	fi

clean:
	rm -f $(EXEC)

regex.sh: open exec
