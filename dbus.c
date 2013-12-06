/*
 *   Copyright (c) 2013
 *   Canonical, Ltd. (All rights reserved)
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include <stdlib.h>
#include <string.h>
#include <apparmor.h>

#include "parser.h"
#include "profile.h"
#include "parser_yacc.h"
#include "dbus.h"

void free_dbus_entry(struct dbus_entry *ent)
{
	if (!ent)
		return;
	free(ent->bus);
	free(ent->name);
	free(ent->peer_label);
	free(ent->path);
	free(ent->interface);
	free(ent->member);

	free(ent);
}

static int list_len(struct value_list *v)
{
	int len = 0;
	struct value_list *tmp;

	list_for_each(v, tmp)
		len++;

	return len;
}

static void move_conditional_value(char **dst_ptr, struct cond_entry *cond_ent)
{
	if (*dst_ptr)
		yyerror("dbus conditional \"%s\" can only be specified once\n",
			cond_ent->name);

	*dst_ptr = cond_ent->vals->value;
	cond_ent->vals->value = NULL;
}

static void move_conditionals(struct dbus_entry *ent, struct cond_entry *conds)
{
	struct cond_entry *cond_ent;

	list_for_each(conds, cond_ent) {
		/* for now disallow keyword 'in' (list) */
		if (!cond_ent->eq)
			yyerror("keyword \"in\" is not allowed in dbus rules\n");
		if (list_len(cond_ent->vals) > 1)
			yyerror("dbus conditional \"%s\" only supports a single value\n",
				cond_ent->name);

		if (strcmp(cond_ent->name, "bus") == 0) {
			move_conditional_value(&ent->bus, cond_ent);
		} else if (strcmp(cond_ent->name, "name") == 0) {
			move_conditional_value(&ent->name, cond_ent);
		} else if (strcmp(cond_ent->name, "label") == 0) {
			move_conditional_value(&ent->peer_label, cond_ent);
		} else if (strcmp(cond_ent->name, "path") == 0) {
			move_conditional_value(&ent->path, cond_ent);
		} else if (strcmp(cond_ent->name, "interface") == 0) {
			move_conditional_value(&ent->interface, cond_ent);
		} else if (strcmp(cond_ent->name, "member") == 0) {
			move_conditional_value(&ent->member, cond_ent);
		} else {
			yyerror("invalid dbus conditional \"%s\"\n",
				cond_ent->name);
		}
	}
}

struct dbus_entry *new_dbus_entry(int mode, struct cond_entry *conds,
				  struct cond_entry *peer_conds)
{
	struct dbus_entry *ent;
	int name_is_subject_cond = 0, message_rule = 0, service_rule = 0;

	ent = (struct dbus_entry*) calloc(1, sizeof(struct dbus_entry));
	if (!ent)
		goto out;

	/* Move the global/subject conditionals over & check the results */
	move_conditionals(ent, conds);
	if (ent->name)
		name_is_subject_cond = 1;
	if (ent->peer_label)
		yyerror("dbus \"label\" conditional can only be used inside of the \"peer=()\" grouping\n");

	/* Move the peer conditionals */
	move_conditionals(ent, peer_conds);

	if (ent->path || ent->interface || ent->member || ent->peer_label ||
	    (ent->name && !name_is_subject_cond))
		message_rule = 1;

	if (ent->name && name_is_subject_cond)
		service_rule = 1;

	if (message_rule && service_rule)
		yyerror("dbus rule contains message conditionals and service conditionals\n");

	/* Copy mode. If no mode was specified, assign an implied mode. */
	if (mode) {
		ent->mode = mode;
		if (ent->mode & ~AA_VALID_DBUS_PERMS)
			yyerror("mode contains unknown dbus accesss\n");
		else if (message_rule && (ent->mode & AA_DBUS_BIND))
			yyerror("dbus \"bind\" access cannot be used with message rule conditionals\n");
		else if (service_rule && (ent->mode & (AA_DBUS_SEND | AA_DBUS_RECEIVE)))
			yyerror("dbus \"send\" and/or \"receive\" accesses cannot be used with service rule conditionals\n");
		else if (ent->mode & AA_DBUS_EAVESDROP &&
			 (ent->path || ent->interface || ent->member ||
			  ent->peer_label || ent->name)) {
			yyerror("dbus \"eavesdrop\" access can only contain a bus conditional\n");
		}
	} else {
		if (message_rule)
			ent->mode = (AA_DBUS_SEND | AA_DBUS_RECEIVE);
		else if (service_rule)
			ent->mode = (AA_DBUS_BIND);
		else
			ent->mode = AA_VALID_DBUS_PERMS;
	}

out:
	free_cond_list(conds);
	free_cond_list(peer_conds);
	return ent;
}

struct dbus_entry *dup_dbus_entry(struct dbus_entry *orig)
{
	struct dbus_entry *ent = NULL;
	ent = (struct dbus_entry *) calloc(1, sizeof(struct dbus_entry));
	if (!ent)
		return NULL;

	DUP_STRING(orig, ent, bus, err);
	DUP_STRING(orig, ent, name, err);
	DUP_STRING(orig, ent, peer_label, err);
	DUP_STRING(orig, ent, path, err);
	DUP_STRING(orig, ent, interface, err);
	DUP_STRING(orig, ent, member, err);
	ent->mode = orig->mode;
	ent->audit = orig->audit;
	ent->deny = orig->deny;

	ent->next = orig->next;

	return ent;

err:
	free_dbus_entry(ent);
	return NULL;
}

void print_dbus_entry(struct dbus_entry *ent)
{
	if (ent->audit)
		fprintf(stderr, "audit ");
	if (ent->deny)
		fprintf(stderr, "deny ");

	fprintf(stderr, "dbus ( ");

	if (ent->mode & AA_DBUS_SEND)
		fprintf(stderr, "send ");
	if (ent->mode & AA_DBUS_RECEIVE)
		fprintf(stderr, "receive ");
	if (ent->mode & AA_DBUS_BIND)
		fprintf(stderr, "bind ");
	if (ent->mode & AA_DBUS_EAVESDROP)
		fprintf(stderr, "eavesdrop ");
	fprintf(stderr, ")");

	if (ent->bus)
		fprintf(stderr, " bus=\"%s\"", ent->bus);
	if ((ent->mode & AA_DBUS_BIND) && ent->name)
		fprintf(stderr, " name=\"%s\"", ent->name);
	if (ent->path)
		fprintf(stderr, " path=\"%s\"", ent->path);
	if (ent->interface)
		fprintf(stderr, " interface=\"%s\"", ent->interface);
	if (ent->member)
		fprintf(stderr, " member=\"%s\"", ent->member);

	if (!(ent->mode & AA_DBUS_BIND) && (ent->peer_label || ent->name)) {
		fprintf(stderr, " peer=( ");
		if (ent->peer_label)
			fprintf(stderr, "label=\"%s\" ", ent->peer_label);
		if (ent->name)
			fprintf(stderr, "name=\"%s\" ", ent->name);
		fprintf(stderr, ")");
	}

	fprintf(stderr, ",\n");
}
