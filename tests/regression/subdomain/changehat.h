/* $Id$ */


/* #define CHANGEHAT_NOT_IN_GLIB */

#define SD_ID_MAGIC     0x8c235e38

#ifdef CHANGEHAT_NOT_IN_LIBRARY
#  ifdef CHANGEHAT_2_4_KERNEL

struct sd_hat {
        char *hat_name;
        unsigned int hat_magic;
};

#define __NR_security   223 
#define SD_CHANGE_HAT   10

_syscall3(int, security, unsigned int, id, unsigned int, call, unsigned long *, args);

int change_hat (char * subprofile, unsigned int token)
{
	struct sd_hat hat;
	unsigned int id = SD_ID_MAGIC;

	hat.hat_name=subprofile;
	hat.hat_magic = token;

	return security(id, SD_CHANGE_HAT, (unsigned long*)&hat);
}

#  else
#    ifdef CHANGEHAT_2_2_KERNEL
#define __NR_change_hat 230

_syscall2(int, change_hat, char *, subdomain, unsigned int, magic_token);

#    endif /* CHANGEHAT_2_2_KERNEL */
#  endif /* CHANGEHAT_2_4_KERNEL */

#else /* !CHANGEHAT_NOT_IN_LIBRARY */
#ifdef USE_COMPAT_IMMUNIX_H
#include <sys/immunix.h>
#else
#include <sys/apparmor.h>
#endif /* USE_COMPAT_IMMUNIX_H */
#endif /* CHANGEHAT_NOT_IN_LIBRARY */

#include <fcntl.h>
#include <string.h>

inline int do_open (char * file)
{
	int fd, rc;
	char buf[128];
	const char *data="hello world";

	fd=open(file, O_RDWR, 0);
	if (fd == -1){
		fprintf(stderr, "FAIL: open %s failed - %s\n",
			file,
			strerror(errno));
		return 1;
	}

        rc=write(fd, data, strlen(data));

        if (rc != strlen(data)){
                fprintf(stderr, "FAIL: write failed - %s\n",
                        strerror(errno));
                return 1;
        }

        (void)lseek(fd, 0, SEEK_SET);
        rc=read(fd, buf, sizeof(buf));

        if (rc != strlen(data)){
                fprintf(stderr, "FAIL: read failed - %s\n",
                        strerror(errno));
                return 1;
        }

        if (memcmp(buf, data, strlen(data)) != 0){
                fprintf(stderr, "FAIL: comparison failed - %s\n",
                        strerror(errno));
                return 1;
        }

	close(fd);

	return 0;
}
