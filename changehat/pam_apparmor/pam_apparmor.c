/* pam_apparmor module */

/*
 * $Id$
 *
 * Written by Jesse Michael <jmichael@suse.de> 2006/08/24
 *
 * Based off of pam_motd by:
 *   Ben Collins <bcollins@debian.org> 2005/10/04
 *   Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
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
	int fd, retval;
	unsigned int magic_token;
	const char *user;

	/* grab the target user name */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		return PAM_USER_UNKNOWN;
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return PAM_PERM_DENIED;
	}

	/* the magic token needs to be non-zero otherwise, we won't be able to 
	   probe for hats */
	do {
		retval = read(fd, (void *) &magic_token, sizeof(magic_token));
		if (retval < 0) {
			return PAM_PERM_DENIED;
		}
	} while (magic_token == 0);

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
				return PAM_PERM_DENIED;
			}
		}
	}

	/* zero out the magic token so an attacker wouldn't be able to just grab 
	   it out of process memory and instead would need to brute force it */
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
