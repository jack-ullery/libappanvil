#define _XOPEN_SOURCE 500

/*
 *	Copyright (C) 2002-2005 Novell/SUSE
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */

#include <stdlib.h>
#include "unix_fd_common.h"

int main(int argc, char *argv[]) {
	exit(get_unix_clientfd(argv[1]));
}
