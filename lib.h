#ifndef __AA_LIB_H_
#define __AA_LIB_H_

#include <dirent.h>

#define autofree __attribute((cleanup(__autofree)))
#define autoclose __attribute((cleanup(__autoclose)))
#define autofclose __attribute((cleanup(__autofclose)))
void __autofree(void *p);
void __autoclose(int *fd);
void __autofclose(FILE **f);

int dirat_for_each(DIR *dir, const char *name, void *data,
		   int (* cb)(DIR *, const char *, struct stat *, void *));

bool isodigit(char c);
long strntol(const char *str, const char **endptr, int base, long maxval,
	     size_t n);
int strn_escseq(const char **pos, const char *chrs, size_t n);
int str_escseq(const char **pos, const char *chrs);

#endif /* __AA_LIB_H_ */
