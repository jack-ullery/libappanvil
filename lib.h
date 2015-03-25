#ifndef __AA_LIB_H_
#define __AA_LIB_H_

#include <sys/apparmor_private.h>

#define autofree __attribute((cleanup(_aa_autofree)))
#define autoclose __attribute((cleanup(_aa_autoclose)))
#define autofclose __attribute((cleanup(_aa_autofclose)))

int dirat_for_each(DIR *dir, const char *name, void *data,
		   int (* cb)(DIR *, const char *, struct stat *, void *));

int isodigit(char c);
long strntol(const char *str, const char **endptr, int base, long maxval,
	     size_t n);
int strn_escseq(const char **pos, const char *chrs, size_t n);
int str_escseq(const char **pos, const char *chrs);

#endif /* __AA_LIB_H_ */
