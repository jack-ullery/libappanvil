/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc.
 *
 */

/*
 * @author Matt Barringer <mbarringer@suse.de>
 */

/*
 * TODO:
 *
 * - Store the audit ID
 * - Convert the text permission mask into a bitmask
 * - Clean up parser grammar
 */


#include <stdlib.h>
#include "aalogparse.h"
#include "parser.h"

/* This is mostly just a wrapper around the code in grammar.y */
aa_log_record *
parse_record(char *str)
{
	if (str == NULL)
		return NULL;

	return _parse_yacc(str);
}

void
free_record(aa_log_record *record)
{
	if (record != NULL)
	{
		if (record->operation != NULL)
			free(record->operation);
		if (record->requested_mask != NULL)
			free(record->requested_mask);
		if (record->denied_mask != NULL)
			free(record->denied_mask);
		if (record->profile != NULL)
			free(record->profile);
		if (record->name != NULL)
			free(record->name);
		if (record->name2 != NULL)
			free(record->name2);
		if (record->attribute != NULL)
			free(record->attribute);
		if (record->parent != NULL)
			free(record->parent);
		if (record->magic_token != NULL)
			free(record->magic_token);
		if (record->info != NULL)
			free(record->info);
		if (record->active_hat != NULL)
			free(record->active_hat);
		free(record);
	}
	return;
}

/* Set all of the fields to appropriate values */
void
_init_log_record(aa_log_record *record)
{
	if (record == NULL)
		return;

	record->version = AA_RECORD_SYNTAX_UNKNOWN;
	record->event = AA_RECORD_INVALID;
	record->pid = 0;
	record->bitmask = 0;
	record->task = 0;

	record->operation = NULL;
	record->denied_mask = NULL;
	record->requested_mask = NULL;
	record->profile = NULL;
	record->name = NULL;
	record->name2 = NULL;
	record->attribute = NULL;
	record->parent = NULL;
	record->magic_token = NULL;
	record->info = NULL;
	record->active_hat = NULL;
	return;
}
