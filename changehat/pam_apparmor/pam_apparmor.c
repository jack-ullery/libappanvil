/* pam_apparmor module */

/*
 * Modified for pam_motd by Ben Collins <bcollins@debian.org>
 *
 * Based off of:
 * $Id: pam_motd.c,v 1.11 2005/09/21 10:01:01 t8m Exp $
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include <security/_pam_macros.h>
/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_SESSION

#include <security/pam_modules.h>

/* --- session management functions (only) --- */

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
     return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
	int fd, retval = PAM_IGNORE;
	unsigned int magic_token = 0xDEADC0ED;
	const void *user;

	/* grab the target user name */
	retval = pam_get_item(pamh, PAM_USER, &user);
	if (retval != PAM_SUCCESS || user == NULL || *(const char *)user == '\0') {
		return PAM_USER_UNKNOWN;
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return PAM_PERM_DENIED;
	}
	retval = read(fd, (void *) &magic_token, sizeof(magic_token));

	close(fd);

	/* change into the user hat */
	retval = change_hat(user, magic_token);
	if (retval < 0) {
		/* failed to change into user hat, so we'll jump back out */
		retval = change_hat(NULL, magic_token);
		if (retval == 0) {
			/* and try to change to the DEFAULT hat instead */
			retval = change_hat("DEFAULT", magic_token);
			if (retval < 0) {
				/* failed to change into default hat, so we'll 
				   jump back out */
				retval = change_hat(NULL, magic_token);
			}
		}
	}

	/* zero out the magic token so we can't get back out */
	memset(&magic_token, 0, sizeof(magic_token));

	return PAM_SUCCESS;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_apparmor_modstruct = {
     "pam_apparmor",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif

/* end of module definition */
