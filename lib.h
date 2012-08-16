#ifndef __AA_LIB_H_
#define __AA_LIB_H_

int dirat_for_each(DIR *dir, const char *name, void *data,
		   int (* cb)(DIR *, const char *, struct stat *, void *));

#endif /* __AA_LIB_H_ */
