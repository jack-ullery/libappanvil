int *ptr;

/*
 *	Copyright (C) 2002-2005 Novell/SUSE
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */

main()
{
	printf("This will cause a sigsegv\n");

	ptr=0;

	*ptr=0xdeadbeef;

	return 0;
}
