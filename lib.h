#ifndef __AA_LIB_H_
#define __AA_LIB_H_

#include <dirent.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

int dirat_for_each(DIR *dir, const char *name, void *data,
		   int (* cb)(DIR *, const char *, struct stat *, void *));

bool isodigit(char c);
long strntol(const char *str, const char **endptr, int base, long maxval,
	     size_t n);
int strn_escseq(const char **pos, const char *chrs, size_t n);
int str_escseq(const char **pos, const char *chrs);

#endif /* __AA_LIB_H_ */
