/*
 *   Copyright (c) 2010
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

/**
 * The mount command, its mix of options and flags, its permissions and
 * mapping are a mess.
 *      mount [-lhV]
 *
 *      mount -a [-fFnrsvw] [-t vfstype] [-O optlist]
 *
 *      mount [-fnrsvw] [-o option[,option]...]  device|dir
 *
 *      mount [-fnrsvw] [-t vfstype] [-o options] device dir
 *
 *----------------------------------------------------------------------
 * Mount flags of no interest for apparmor mediation
 * -a, --all
 * -F fork for simultaneous mount
 * -f fake, do everything except that actual system call
 * -h --help
 * -i, --internal-only
 * -n mount without writing in /etc/mtab
 * -O <optlist> limits what is auto mounted
 * -p, --pass-fd num
 * -s     Tolerate sloppy mount options
 * -U uuid
 * -V --version
 * --no-canonicalize
 *
 *----------------------------------------------------------------------
 * what do we do with these
 * -l	list?
 * -L <label> label
 * -v --verbose		deprecated
 *
 *----------------------------------------------------------------------
 * Filesystem type
 * -t <vfstype>
 *    vfstype=<vfstype>
 *
 *----------------------------------------------------------------------
 * Mount Flags/options (-o --options)
 *  -o option[,option]
 * 
 * The Linux kernel has 32 fs - independent mount flags, that mount command
 * is responsible for stripping out and mapping to a 32 bit flags field.
 * The mount commands mapping is documented below.
 *
 * Unfortunately we can not directly use this mapping as we need to be able
 * represent, whether none, 1 or both options of a flag can be present for
 * example
 *    ro, and rw information is stored in a single bit.  But we need 2 bits
 *    of information.
 *    ro - the mount can only be readonly
 *    rw - the mount can only be rw
 *    ro/rw - the mount can be either ro/rw
 *    the fourth state of neither ro/rw does not exist, but still we need
 *    >1 bit to represent the possible choices
 *
 * The fs specific mount options are passed into the kernel as a string
 * to be interpreted by the filesystem.
 *
 *
 * #define MS_RDONLY	 1		Mount read-only
 *	ro -r --read-only	[source] dest
 *	rw -w
 * #define MS_NOSUID	 2		Ignore suid and sgid bits
 *	nosuid
 *	suid
 * #define MS_NODEV	 4		Disallow access to device special files
 *	nodev
 *	dev
 * #define MS_NOEXEC	 8		Disallow program execution
 *	noexec
 *	exec
 * #define MS_SYNCHRONOUS	16	Writes are synced at once
 *	sync
 *	async
 * #define MS_REMOUNT	32		Alter flags of a mounted FS
 *	remount			source dest
 * #define MS_MANDLOCK	64		Allow mandatory locks on an FS
 *	mand
 *	nomand
 * #define MS_DIRSYNC	128		Directory modifications are synchronous
 *	dirsync
 * #define MS_NOATIME	1024		Do not update access times
 *	noatime
 *	atime
 * #define MS_NODIRATIME	2048	Do not update directory access times
 *	nodiratime
 *	diratime
 * #define MS_BIND		4096
 *	--bind -B		source dest
 * #define MS_MOVE		8192
 *	--move -M		source dest
 * #define MS_REC		16384
 *	--rbind -R		source dest
 *	--make-rshared		dest
 *	--make-rslave		dest
 *	--make-rprivate		dest
 *	--make-runbindable	dest
 * #define MS_VERBOSE	32768		MS_VERBOSE is deprecated
 * #define MS_SILENT	32768
 *	silent
 *	load
 * #define MS_POSIXACL	(1<<16)		VFS does not apply the umask
 *	acl
 *	noacl
 * #define MS_UNBINDABLE	(1<<17)	change to unbindable
 *	--make-unbindable	dest
 * #define MS_PRIVATE	(1<<18)		change to private
 *	--make-private		dest
 * #define MS_SLAVE	(1<<19)		change to slave
 *	--make-slave		dest
 * #define MS_SHARED	(1<<20)		change to shared
 *	--make-shared		dest
 * #define MS_RELATIME	(1<<21)		Update atime relative to mtime/ctime
 *	relatime
 *	norelatime
 * #define MS_KERNMOUNT	(1<<22)		this is a kern_mount call
 * #define MS_I_VERSION	(1<<23)		Update inode I_version field
 *	iversion
 *	noiversion
 * #define MS_STRICTATIME	(1<<24)	Always perform atime updates
 *	strictatime
 *	nostrictatime
 * #define MS_NOSEC	(1<<28)
 * #define MS_BORN		(1<<29)
 * #define MS_ACTIVE	(1<<30)
 * #define MS_NOUSER	(1<<31)
 *	nouser
 *	user
 *
 * other mount options of interest
 *
 *   selinux
 *     context=<context>
 *     fscontext=<context>
 *     defcontext=<context>,
 *     rootcontext=<context>
 *
 *   defaults -> rw, suid,  dev,  exec,  auto,  nouser,  async
 *   owner -> implies nosuid  and  nodev
 *   users -> implies noexec, nosuid, and nodev
 *
 *----------------------------------------------------------------------
 * AppArmor mount rules
 *
 * AppArmor mount rules try to leverage mount syntax within apparmor syntax
 * this can not be done entirely but it is largely covered.
 *
 * The general mount syntax is
 * [audit] [deny] [owner] mount [conds]* [source] [ -> [conds] path],
 * [audit] [deny] remount [conds]* [path],
 * [audit] [deny] umount [conds]* [path],
 *
 * Note: leading owner option applies owner condition to both sours and dest
 *       path.
 *
 * where [conds] can be
 * fstype=<expr>
 * options=<expr>
 * owner[=<expr>]
 *
 * <expr> := <re> | '(' (<re>[,])+ ')'
 *
 * If a condition is not specified then it is assumed to match all possible
 * entries for it.  ie. a missing fstype means all fstypes are matched.
 * However if a condition is specified then the rule only grants permission
 * for mounts matching the specified pattern.
 *
 * Examples.
 * mount,		# allow any mount
 * mount /dev/foo,	# allow mounting of /dev/foo anywhere
 * mount options=ro /dev/foo,  #allow mounting /dev/foo as read only
 * mount options=(ro,foo) /dev/foo,
 * mount options=ro options=foo /dev/foo,
 * mount fstype=overlayfs options=(rw,upperdir=/tmp/upper/,lowerdir=/) overlay -> /mnt/
 *
 *----------------------------------------------------------------------
 * pivotroot
 *   pivotroot [oldroot=<value>] <path> -> <profile>
 *   pivotroot <path> -> {  }
 *
 *----------------------------------------------------------------------
 * chroot
 *   chroot <path> -> <profile>
 *   chroot <path> -> {  }
 *
 *----------------------------------------------------------------------
 * AppArmor mount rule encoding
 *
 * TODO:
 *   add semantic checking of options against specified filesytem types
 *   to catch mount options that can't be covered.
 *
 *
 */


#include <stdlib.h>
#include <string.h>

#include "parser.h"
#include "mount.h"

struct mnt_keyword_table {
	char *keyword;
	unsigned int set;
	unsigned int clear;
};

static struct mnt_keyword_table mnt_opts_table[] = {
	{"ro",			MS_RDONLY, 0},
	{"r",			MS_RDONLY, 0},
	{"read-only",		MS_RDONLY, 0},
	{"rw",			0, MS_RDONLY},
	{"w",			0, MS_RDONLY},
	{"suid",		0, MS_NOSUID},
	{"nosuid",		MS_NOSUID, 0},
	{"dev",			0, MS_NODEV},
	{"nodev",		MS_NODEV, 0},
	{"exec",		0, MS_NOEXEC},
	{"noexec",		MS_NOEXEC, 0},
	{"sync",		MS_SYNC, 0},
	{"async",		0, MS_SYNC},
	{"remount",		MS_REMOUNT, 0},
	{"mand",		MS_MAND, 0},
	{"nomand",		0, MS_MAND},
	{"dirsync",		MS_DIRSYNC, 0},
	{"atime",		0, MS_NOATIME},
	{"noatime",		MS_NOATIME, 0},
	{"diratime",		0, MS_NODIRATIME},
	{"nodiratime",		MS_NODIRATIME, 0},
	{"bind",		MS_BIND, 0},
	{"B",			MS_BIND, 0},
	{"move",		MS_MOVE, 0},
	{"M",			MS_MOVE, 0},
	{"rbind",		MS_RBIND, 0},
	{"R",			MS_RBIND, 0},
	{"verbose",		MS_VERBOSE, 0},
	{"silent",		MS_SILENT, 0},
	{"load",		0, MS_SILENT},
	{"acl",			MS_ACL, 0},
	{"noacl",		0, MS_ACL},
	{"make-unbindable",	MS_UNBINDABLE, 0},
	{"make-runbindable",	MS_RUNBINDABLE, 0},
	{"make-private",	MS_PRIVATE, 0},
	{"make-rprivate",	MS_RPRIVATE, 0},
	{"make-slave",		MS_SLAVE, 0},
	{"make-rslave",		MS_RSLAVE, 0},
	{"make-shared",		MS_SHARED, 0},
	{"make-rshared",	MS_RSHARED, 0},

	{"relatime",		MS_RELATIME, 0},
	{"norelatime",		0, MS_NORELATIME},
	{"iversion",		MS_IVERSION, 0},
	{"noiversion",		0, MS_IVERSION},
	{"strictatime",		MS_STRICTATIME, 0},
	{"user",		0, MS_NOUSER},
	{"nouser",		MS_NOUSER, 0},

	{NULL, 0, 0}
};

static struct mnt_keyword_table mnt_conds_table[] = {
	{"options", MNT_SRC_OPT, MNT_COND_OPTIONS},
	{"option", MNT_SRC_OPT, MNT_COND_OPTIONS},
	{"fstype", MNT_SRC_OPT | MNT_DST_OPT, MNT_COND_FSTYPE},
	{"vfstype", MNT_SRC_OPT | MNT_DST_OPT, MNT_COND_FSTYPE},

	{NULL, 0, 0}
};

static int find_mnt_keyword(struct mnt_keyword_table *table, const char *name)
{
	int i;
	for (i = 0; table[i].keyword; i++) {
		if (strcmp(name, table[i].keyword) == 0)
			return i;
	}

	return -1;
}

int is_valid_mnt_cond(const char *name, int src)
{
	int i;
	i = find_mnt_keyword(mnt_conds_table, name);
	if (i != -1)
		return (mnt_conds_table[i].set & src);
	return -1;
}

static unsigned int extract_flags(struct value_list **list, unsigned int *inv)
{
	unsigned int flags = 0;
	*inv = 0;

	struct value_list *entry, *tmp, *prev = NULL;
	list_for_each_safe(*list, entry, tmp) {
		int i;
		i = find_mnt_keyword(mnt_opts_table, entry->value);
		if (i != -1) {
			flags |= mnt_opts_table[i].set;
			*inv |= mnt_opts_table[i].clear;
			PDEBUG(" extracting mount flag %s req: 0x%x inv: 0x%x"
			       " => req: 0x%x inv: 0x%x\n",
			       entry->value, mnt_opts_table[i].set,
			       mnt_opts_table[i].clear, flags, *inv);
			if (prev)
				prev->next = tmp;
			if (entry == *list)
				*list = tmp;
			entry->next = NULL;
			free_value_list(entry);
		} else
			prev = entry;
	}

	return flags;
}

static struct value_list *extract_fstype(struct cond_entry **conds)
{
	struct value_list *list = NULL;

	struct cond_entry *entry, *tmp, *prev = NULL;

	list_for_each_safe(*conds, entry, tmp) {
		if (strcmp(entry->name, "fstype") == 0 ||
		    strcmp(entry->name, "vfstype") == 0) {
			PDEBUG("  extracting fstype\n");
			if (prev)
				prev->next = tmp;
			if (entry == *conds)
				*conds = tmp;
			entry->next = NULL;
			list_append(entry->vals, list);
			list = entry->vals;
			entry->vals = NULL;
			free_cond_entry(entry);
		} else
			prev = entry;
	}

	return list;
}

static struct value_list *extract_options(struct cond_entry **conds, int eq)
{
	struct value_list *list = NULL;

	struct cond_entry *entry, *tmp, *prev = NULL;

	list_for_each_safe(*conds, entry, tmp) {
		if ((strcmp(entry->name, "options") == 0 ||
		     strcmp(entry->name, "option") == 0) &&
		    entry->eq == eq) {
			if (prev)
				prev->next = tmp;
			if (entry == *conds)
				*conds = tmp;
			entry->next = NULL;
			PDEBUG("  extracting option %s\n", entry->name);
			list_append(entry->vals, list);
			list = entry->vals;
			entry->vals = NULL;
			free_cond_entry(entry);
		} else
			prev = entry;
	}

	return list;
}

struct mnt_entry *new_mnt_entry(struct cond_entry *src_conds, char *device,
				struct cond_entry *dst_conds __unused, char *mnt_point,
				int allow)
{
	/* FIXME: dst_conds are ignored atm */

	struct mnt_entry *ent;
	ent = (struct mnt_entry *) calloc(1, sizeof(struct mnt_entry));
	if (ent) {
		ent->mnt_point = mnt_point;
		ent->device = device;
		ent->dev_type = extract_fstype(&src_conds);

		ent->flags = 0;
		ent->inv_flags = 0;

		if (src_conds) {
			unsigned int flags = 0, inv_flags = 0;
			struct value_list *list = extract_options(&src_conds, 0);

			ent->opts = extract_options(&src_conds, 1);
			if (ent->opts)
				ent->flags = extract_flags(&ent->opts,
							   &ent->inv_flags);

			if (list) {
				flags = extract_flags(&list, &inv_flags);
				/* these flags are optional so set both */
				flags |= inv_flags;
				inv_flags |= flags;

				ent->flags |= flags;
				ent->inv_flags |= inv_flags;

				if (ent->opts)
					list_append(ent->opts, list);
				else if (list)
					ent->opts = list;
			}
		}

		if (allow & AA_DUMMY_REMOUNT) {
			allow = AA_MAY_MOUNT;
			ent->flags |= MS_REMOUNT;
			ent->inv_flags = 0;
		} else if (!(ent->flags | ent->inv_flags)) {
			/* no flag options, and not remount, allow everything */
			ent->flags = MS_ALL_FLAGS;
			ent->inv_flags = MS_ALL_FLAGS;
		}

		ent->allow = allow;

		if (src_conds) {
			PERROR("  unsupported mount conditions\n");
			exit(1);
		}
	}

	return ent;
}

void free_mnt_entry(struct mnt_entry *ent)
{
	if (!ent)
		return;

	free_mnt_entry(ent->next);
	free_value_list(ent->opts);
	free_value_list(ent->dev_type);
	free(ent->device);
	free(ent->mnt_point);
	free(ent->trans);

	free(ent);
}


struct mnt_entry *dup_mnt_entry(struct mnt_entry *orig)
{
	struct mnt_entry *entry = NULL;

	entry = (struct mnt_entry *) calloc(1, sizeof(struct mnt_entry));
	if (!entry)
		return NULL;

	entry->mnt_point = orig->mnt_point ? strdup(orig->mnt_point) : NULL;
	entry->device = orig->device ? strdup(orig->device) : NULL;
	entry->trans = orig->trans ? strdup(orig->trans) : NULL;

	entry->dev_type = dup_value_list(orig->dev_type);
	entry->opts = dup_value_list(orig->opts);

	entry->flags = orig->flags;
	entry->inv_flags = orig->inv_flags;

	entry->allow = orig->allow;
	entry->audit = orig->audit;
	entry->deny = orig->deny;

	entry->next = orig->next;

	return entry;
}

void print_mnt_entry(struct mnt_entry *entry)
{
	if (entry->allow & AA_MAY_MOUNT)
		fprintf(stderr, "mount");
	else if (entry->allow & AA_MAY_UMOUNT)
		fprintf(stderr, "umount");
	else if (entry->allow & AA_MAY_PIVOTROOT)
		fprintf(stderr, "pivotroot");
	else
		fprintf(stderr, "error: unknonwn mount perm");

	fprintf(stderr, " (0x%x - 0x%x) ", entry->flags, entry->inv_flags);
	if (entry->dev_type) {
		fprintf(stderr, " type=");
		print_value_list(entry->dev_type);
	}
	if (entry->opts) {
		fprintf(stderr, " options=");
		print_value_list(entry->opts);
	}
	if (entry->device)
		fprintf(stderr, " %s", entry->device);
	if (entry->mnt_point)
		fprintf(stderr, " -> %s", entry->mnt_point);
	if (entry->trans)
		fprintf(stderr, " -> %s", entry->trans);

	fprintf(stderr, " %s (0x%x/0x%x)", entry->deny ? "deny" : "", entry->allow, entry->audit); 
	fprintf(stderr, ",\n");
}
