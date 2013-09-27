/*
 *   Copyright (c) 2012
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
 */

#include "profile.h"

#include <stdio.h>
#include <stdlib.h>

bool deref_profileptr_lt::operator()(Profile * const &lhs, Profile * const &rhs) const
{
  return *lhs < *rhs;
};

pair<ProfileList::iterator,bool> ProfileList::insert(Profile *p)
{
	return list.insert(p);
}

void ProfileList::erase(ProfileList::iterator pos)
{
	list.erase(pos);
}

void ProfileList::clear(void)
{
	for(ProfileList::iterator i = list.begin(); i != list.end(); ) {
		ProfileList::iterator k = i++;
		delete *k;
		list.erase(k);
	}
}

void ProfileList::dump(void)
{
	for(ProfileList::iterator i = list.begin(); i != list.end(); i++) {
		(*i)->dump();
	}
}

void ProfileList::dump_profile_names(bool children)
{
	for (ProfileList::iterator i = list.begin(); i != list.end();i++) {
		(*i)->dump_name(true);
		printf("\n");
		if (children && !(*i)->hat_table.empty())
			(*i)->hat_table.dump_profile_names(children);
	}
}

Profile::~Profile()
{
	hat_table.clear();
	free_cod_entries(entries);
	free_mnt_entries(mnt_ents);
	free_dbus_entries(dbus_ents);
	if (dfa.rules)
		aare_delete_ruleset(dfa.rules);
	if (dfa.dfa)
		free(dfa.dfa);
	if (policy.rules)
		aare_delete_ruleset(policy.rules);
	if (policy.dfa)
		free(policy.dfa);
	if (name)
		free(name);
	if (attachment)
		free(attachment);
	if (ns)
		free(ns);
	if (net.allow)
		free(net.allow);
	if (net.audit)
		free(net.audit);
	if (net.deny)
		free(net.deny);
	if (net.quiet)
		free(net.quiet);
}

