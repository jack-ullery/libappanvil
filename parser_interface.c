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
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#define _(s) gettext(s)

#include "parser.h"
#include "profile.h"
#include "libapparmor_re/apparmor_re.h"

#include <unistd.h>
#include <linux/unistd.h>

/* only for x86 at the moment */
#include <endian.h>
#include <byteswap.h>
#include <libintl.h>
#define _(s) gettext(s)

#define u8  unsigned char
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define BUFFERINC 65536
//#define BUFFERINC 16

#if __BYTE_ORDER == __BIG_ENDIAN
#  define cpu_to_le16(x) ((u16)(bswap_16 ((u16) x)))
#  define cpu_to_le32(x) ((u32)(bswap_32 ((u32) x)))
#  define cpu_to_le64(x) ((u64)(bswap_64 ((u64) x)))
#else
#  define cpu_to_le16(x) ((u16)(x))
#  define cpu_to_le32(x) ((u32)(x))
#  define cpu_to_le64(x) ((u64)(x))
#endif

#define SD_CODE_SIZE (sizeof(u8))
#define SD_STR_LEN (sizeof(u16))

#define SUBDOMAIN_INTERFACE_DFA_VERSION 5

int __sd_serialize_profile(int option, Profile *prof);

static void print_error(int error)
{
	switch (error) {
	case -ESPIPE:
		PERROR(_("Bad write position\n"));
		break;
	case -EPERM:
		PERROR(_("Permission denied\n"));
		break;
	case -ENOMEM:
		PERROR(_("Out of memory\n"));
		break;
	case -EFAULT:
		PERROR(_("Couldn't copy profile: Bad memory address\n"));
		break;
	case -EPROTO:
		PERROR(_("Profile doesn't conform to protocol\n"));
		break;
	case -EBADMSG:
		PERROR(_("Profile does not match signature\n"));
		break;
	case -EPROTONOSUPPORT:
		PERROR(_("Profile version not supported by Apparmor module\n"));
		break;
	case -EEXIST:
		PERROR(_("Profile already exists\n"));
		break;
	case -ENOENT:
		PERROR(_("Profile doesn't exist\n"));
		break;
	case -EACCES:
		PERROR(_("Permission denied; attempted to load a profile while confined?\n"));
		break;
	default:
		PERROR(_("Unknown error (%d): %s\n"), -error, strerror(-error));
		break;
	}
}

int load_profile(int option, Profile *prof)
{
	int retval = 0;
	int error = 0;

	PDEBUG("Serializing policy for %s.\n", prof->name);
	retval = __sd_serialize_profile(option, prof);

	if (retval < 0) {
		error = retval;	/* yeah, we'll just report the last error */
		switch (option) {
		case OPTION_ADD:
			PERROR(_("%s: Unable to add \"%s\".  "),
			       progname, prof->name);
			print_error(error);
			break;
		case OPTION_REPLACE:
			PERROR(_("%s: Unable to replace \"%s\".  "),
			       progname, prof->name);
			print_error(error);
			break;
		case OPTION_REMOVE:
			PERROR(_("%s: Unable to remove \"%s\".  "),
			       progname, prof->name);
			print_error(error);
			break;
		case OPTION_STDOUT:
			PERROR(_("%s: Unable to write to stdout\n"),
			       progname);
			break;
		case OPTION_OFILE:
			PERROR(_("%s: Unable to write to output file\n"),
			       progname);
		default:
			PERROR(_("%s: ASSERT: Invalid option: %d\n"),
			       progname, option);
			exit(1);
			break;
		}

	} else if (conf_verbose) {
		switch (option) {
		case OPTION_ADD:
			printf(_("Addition succeeded for \"%s\".\n"),
			       prof->name);
			break;
		case OPTION_REPLACE:
			printf(_("Replacement succeeded for \"%s\".\n"),
			       prof->name);
			break;
		case OPTION_REMOVE:
			printf(_("Removal succeeded for \"%s\".\n"),
			       prof->name);
			break;
		case OPTION_STDOUT:
		case OPTION_OFILE:
			break;
		default:
			PERROR(_("%s: ASSERT: Invalid option: %d\n"),
			       progname, option);
			exit(1);
			break;
		}
	}

	return error;
}



enum sd_code {
	SD_U8,
	SD_U16,
	SD_U32,
	SD_U64,
	SD_NAME,		/* same as string except it is items name */
	SD_STRING,
	SD_BLOB,
	SD_STRUCT,
	SD_STRUCTEND,
	SD_LIST,
	SD_LISTEND,
	SD_ARRAY,
	SD_ARRAYEND,
	SD_OFFSET
};

const char *sd_code_names[] = {
	"SD_U8",
	"SD_U16",
	"SD_U32",
	"SD_U64",
	"SD_NAME",
	"SD_STRING",
	"SD_BLOB",
	"SD_STRUCT",
	"SD_STRUCTEND",
	"SD_LIST",
	"SD_LISTEND",
	"SD_ARRAY",
	"SD_ARRAYEND",
	"SD_OFFSET"
};

/* Currently we will just use a contiguous block of memory
   be we are going to just hide this for the moment.  */
struct __sdserialize {
	void *buffer;
	void *pos;
	void *extent;
};

sd_serialize *alloc_sd_serial(void)
{
	sd_serialize *p = (sd_serialize *) calloc(1, sizeof(sd_serialize));
	if (!p)
		return NULL;
	p->buffer = malloc(BUFFERINC);
	if (!p->buffer) {
		free(p);
		return NULL;
	}
	p->pos = p->buffer;
	p->extent = p->buffer + BUFFERINC;
	return p;
}

void free_sd_serial(sd_serialize *p)
{
	if (p) {
		if (p->buffer)
			free(p->buffer);
		free(p);
	}
}

/*check if something of size length is in sd_serial bounds */
static inline int sd_inbounds(sd_serialize *p, int size)
{
	return (p->pos + size <= p->extent);
}

static inline void sd_inc(sd_serialize *p, int size)
{
	if (sd_inbounds(p, size)) {
		p->pos += size;
	} else {
		PERROR(_("PANIC bad increment buffer %p pos %p ext %p size %d res %p\n"),
		       p->buffer, p->pos, p->extent, size, p->pos + size);
		exit(-1);
	}
}

inline long sd_serial_size(sd_serialize *p)
{
	return (long) (p->pos) - (long) (p->buffer);
}

/* routines for writing data to the serialization buffer */
inline int sd_prepare_write(sd_serialize *p, enum sd_code code, size_t size)
{
	int num = (size / BUFFERINC) + 1;
	if (p->pos + SD_CODE_SIZE + size > p->extent) {
		long pos;
		/* try and reallocate the buffer */
		void *buffer = malloc((long)(p->extent) - (long)(p->buffer) + (BUFFERINC * num));
		memcpy(buffer, p->buffer, (long)(p->extent) - (long)(p->buffer));

		pos = (long)(p->pos) - (long)(p->buffer);
		if (buffer == NULL || errno == ENOMEM)
			return 0;

		p->extent = buffer + ((long)(p->extent) - (long)(p->buffer)) + (BUFFERINC * num);
		free(p->buffer);
		p->buffer = buffer;
		p->pos = buffer + pos;
	}
	*(u8 *) (p->pos) = code;
	sd_inc(p, SD_CODE_SIZE);
	return 1;
}

inline int sd_write8(sd_serialize *p, u8 b)
{
	u8 *c;
	if (!sd_prepare_write(p, SD_U8, sizeof(b)))
		return 0;
	c = (u8 *) p->pos;
	*c = b;
	sd_inc(p, 1);
	return 1;
}

inline int sd_write16(sd_serialize *p, u16 b)
{
	u16 tmp;
	if (!sd_prepare_write(p, SD_U16, sizeof(b)))
		return 0;
	tmp = cpu_to_le16(b);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	return 1;
}

inline int sd_write32(sd_serialize *p, u32 b)
{
	u32 tmp;
	if (!sd_prepare_write(p, SD_U32, sizeof(b)))
		return 0;
	tmp = cpu_to_le32(b);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	return 1;
}

inline int sd_write64(sd_serialize *p, u64 b)
{
	u64 tmp;
	if (!sd_prepare_write(p, SD_U64, sizeof(b)))
		return 0;
	tmp = cpu_to_le64(b);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	return 1;
}

inline int sd_write_name(sd_serialize *p, const char *name)
{
	long size = 0;
	PDEBUG("Writing name '%s'\n", name);
	if (name) {
		u16 tmp;
		size = strlen(name) + 1;
		if (!sd_prepare_write(p, SD_NAME, SD_STR_LEN + size))
			return 0;
		tmp = cpu_to_le16(size);
		memcpy(p->pos, &tmp, sizeof(tmp));
		sd_inc(p, sizeof(tmp));
		memcpy(p->pos, name, size);
		sd_inc(p, size);
	}
	return 1;
}

inline int sd_write_blob(sd_serialize *p, void *b, int buf_size, char *name)
{
	u32 tmp;
	if (!sd_write_name(p, name))
		return 0;
	if (!sd_prepare_write(p, SD_BLOB, 4 + buf_size))
		return 0;
	tmp = cpu_to_le32(buf_size);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	memcpy(p->pos, b, buf_size);
	sd_inc(p, buf_size);
	return 1;
}

#define align64(X) (((size_t) (X) + (size_t) 7) & ~((size_t) 7))
inline int sd_write_aligned_blob(sd_serialize *p, void *b, int buf_size,
				 const char *name)
{
	size_t pad;
	u32 tmp;
	if (!sd_write_name(p, name))
		return 0;
	pad = align64(((long)(p->pos + 5) - (long)(p->buffer)) - ((long)(p->pos + 5) - (long)(p->buffer)));
	if (!sd_prepare_write(p, SD_BLOB, 4 + buf_size + pad))
		return 0;
	tmp = cpu_to_le32(buf_size + pad);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	memset(p->pos, 0, pad);
	sd_inc(p, pad);
	memcpy(p->pos, b, buf_size);
	sd_inc(p, buf_size);
	return 1;
}

static int sd_write_strn(sd_serialize *p, char *b, int size, const char *name)
{
	u16 tmp;
	if (!sd_write_name(p, name))
		return 0;
	if (!sd_prepare_write(p, SD_STRING, SD_STR_LEN + size))
		return 0;
	tmp = cpu_to_le16(size);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	memcpy(p->pos, b, size);
	sd_inc(p, size);
	return 1;
}

inline int sd_write_string(sd_serialize *p, char *b, const char *name)
{
	return sd_write_strn(p, b, strlen(b) + 1, name);
}

inline int sd_write_struct(sd_serialize *p, const char *name)
{
	if (!sd_write_name(p, name))
		return 0;
	if (!sd_prepare_write(p, SD_STRUCT, 0))
		return 0;
	return 1;
}

inline int sd_write_structend(sd_serialize *p)
{
	if (!sd_prepare_write(p, SD_STRUCTEND, 0))
		return 0;
	return 1;
}

inline int sd_write_array(sd_serialize *p, const char *name, int size)
{
	u16 tmp;
	if (!sd_write_name(p, name))
		return 0;
	if (!sd_prepare_write(p, SD_ARRAY, 2))
		return 0;
	tmp = cpu_to_le16(size);
	memcpy(p->pos, &tmp, sizeof(tmp));
	sd_inc(p, sizeof(tmp));
	return 1;
}

inline int sd_write_arrayend(sd_serialize *p)
{
	if (!sd_prepare_write(p, SD_ARRAYEND, 0))
		return 0;
	return 1;
}

inline int sd_write_list(sd_serialize *p, const char *name)
{
	if (!sd_write_name(p, name))
		return 0;
	if (!sd_prepare_write(p, SD_LIST, 0))
		return 0;
	return 1;
}

inline int sd_write_listend(sd_serialize *p)
{
	if (!sd_prepare_write(p, SD_LISTEND, 0))
		return 0;
	return 1;
}

int sd_serialize_dfa(sd_serialize *p, void *dfa, size_t size)
{
	if (dfa && !sd_write_aligned_blob(p, dfa, size, "aadfa"))
		return 0;

	return 1;
}

int sd_serialize_rlimits(sd_serialize *p, struct aa_rlimits *limits)
{
	int i;
	if (!limits->specified)
		return 1;
	if (!sd_write_struct(p, "rlimits"))
		return 0;
	if (!sd_write32(p, limits->specified))
		return 0;
	if (!sd_write_array(p, NULL, RLIM_NLIMITS))
		return 0;
	for (i = 0; i < RLIM_NLIMITS; i++) {
		if (!sd_write64(p, limits->limits[i]))
			return 0;
	}
	if (!sd_write_arrayend(p))
		return 0;
	if (!sd_write_structend(p))
		return 0;
	return 1;
}

int sd_serialize_xtable(sd_serialize *p, char **table)
{
	int count, i;
	if (!table[4])
		return 1;
	if (!sd_write_struct(p, "xtable"))
		return 0;
	count = 0;
	for (i = 4; i < AA_EXEC_COUNT; i++) {
		if (table[i])
			count++;
	}

	if (!sd_write_array(p, NULL, count))
		return 0;

	for (i = 4; i < count + 4; i++) {
		int len = strlen(table[i]) + 1;

		/* if its a namespace make sure the second : is overwritten
		 * with 0, so that the namespace and name are \0 seperated
		 */
		if (*table[i] == ':') {
			char *tmp = table[i] + 1;
			strsep(&tmp, ":");
		}
		if (!sd_write_strn(p, table[i], len, NULL))
			return 0;

	}
	if (!sd_write_arrayend(p))
		return 0;

	if (!sd_write_structend(p))
		return 0;
	return 1;
}

int count_file_ents(struct cod_entry *list)
{
	struct cod_entry *entry;
	int count = 0;
	list_for_each(list, entry) {
		if (entry->pattern_type == ePatternBasic) {
			count++;
		}
	}
	return count;
}

int count_tailglob_ents(struct cod_entry *list)
{
	struct cod_entry *entry;
	int count = 0;
	list_for_each(list, entry) {
		if (entry->pattern_type == ePatternTailGlob) {
			count++;
		}
	}
	return count;
}

int sd_serialize_profile(sd_serialize *p, Profile *profile,
			 int flattened)
{
	uint64_t allowed_caps;

	if (!sd_write_struct(p, "profile"))
		return 0;
	if (flattened) {
		assert(profile->parent);
		int res;

		char *name = (char *) malloc(3 + strlen(profile->name) +
				    strlen(profile->parent->name));
		if (!name)
			return 0;
		sprintf(name, "%s//%s", profile->parent->name, profile->name);
		res = sd_write_string(p, name, NULL);
		free(name);
		if (!res)
			return 0;
	} else {
		if (!sd_write_string(p, profile->name, NULL))
			return 0;
	}

	/* only emit this if current kernel at least supports "create" */
	if (perms_create) {
		if (profile->xmatch) {
			if (!sd_serialize_dfa(p, profile->xmatch, profile->xmatch_size))
				return 0;
			if (!sd_write32(p, profile->xmatch_len))
				return 0;
		}
	}

	if (!sd_write_struct(p, "flags"))
		return 0;
	/* used to be flags.debug, but that's no longer supported */
	if (!sd_write32(p, profile->flags.hat))
		return 0;
	if (!sd_write32(p, profile->flags.complain))
		return 0;
	if (!sd_write32(p, profile->flags.audit))
		return 0;
	if (!sd_write_structend(p))
		return 0;
	if (profile->flags.path) {
		int flags = 0;
		if (profile->flags.path & PATH_CHROOT_REL)
			flags |= 0x8;
		if (profile->flags.path & PATH_MEDIATE_DELETED)
			flags |= 0x10000;
		if (profile->flags.path & PATH_ATTACH)
			flags |= 0x4;
		if (profile->flags.path & PATH_CHROOT_NSATTACH)
			flags |= 0x10;

		if (!sd_write_name(p, "path_flags") ||
		    !sd_write32(p, flags))
			return 0;
	}

#define low_caps(X) ((u32) ((X) & 0xffffffff))
#define high_caps(X) ((u32) (((X) >> 32) & 0xffffffff))
	allowed_caps = (profile->caps.allow) & ~profile->caps.deny;
	if (!sd_write32(p, low_caps(allowed_caps)))
		return 0;
	if (!sd_write32(p, low_caps(allowed_caps & profile->caps.audit)))
		return 0;
	if (!sd_write32(p, low_caps(profile->caps.deny & profile->caps.quiet)))
		return 0;
	if (!sd_write32(p, 0))
		return 0;

	if (!sd_write_struct(p, "caps64"))
		return 0;
	if (!sd_write32(p, high_caps(allowed_caps)))
		return 0;
	if (!sd_write32(p, high_caps(allowed_caps & profile->caps.audit)))
		return 0;
	if (!sd_write32(p, high_caps(profile->caps.deny & profile->caps.quiet)))
		return 0;
	if (!sd_write32(p, 0))
		return 0;
	if (!sd_write_structend(p))
		return 0;

	if (!sd_serialize_rlimits(p, &profile->rlimits))
		return 0;

	if (profile->net.allow && kernel_supports_network) {
		size_t i;
		if (!sd_write_array(p, "net_allowed_af", get_af_max()))
			return 0;
		for (i = 0; i < get_af_max(); i++) {
		    u16 allowed = profile->net.allow[i] &
			~profile->net.deny[i];
			if (!sd_write16(p, allowed))
				return 0;
			if (!sd_write16(p, allowed & profile->net.audit[i]))
				return 0;
			if (!sd_write16(p, profile->net.deny[i] & profile->net.quiet[i]))
				return 0;
		}
		if (!sd_write_arrayend(p))
			return 0;
	} else if (profile->net.allow)
		pwarn(_("profile %s network rules not enforced\n"), profile->name);

	if (profile->policy.dfa) {
		if (!sd_write_struct(p, "policydb"))
			return 0;
		if (!sd_serialize_dfa(p, profile->policy.dfa, profile->policy.size))
			return 0;
		if (!sd_write_structend(p))
			return 0;
	}

	/* either have a single dfa or lists of different entry types */
	if (!sd_serialize_dfa(p, profile->dfa.dfa, profile->dfa.size))
		return 0;

	if (!sd_serialize_xtable(p, profile->exec_table))
		return 0;

	if (!sd_write_structend(p))
		return 0;

	return 1;
}

int sd_serialize_top_profile(sd_serialize *p, Profile *profile)
{
	int version;

	version = SUBDOMAIN_INTERFACE_DFA_VERSION;

	if (!sd_write_name(p, "version"))
		return 0;

	if (!sd_write32(p, version))
		return 0;

	if (profile_ns) {
		if (!sd_write_string(p, profile_ns, "namespace"))
			return 0;
	} else if (profile->ns) {
		if (!sd_write_string(p, profile->ns, "namespace"))
			return 0;
	}

	return sd_serialize_profile(p, profile, profile->parent ? 1 : 0);
}

int cache_fd = -1;
int __sd_serialize_profile(int option, Profile *prof)
{
	int fd = -1;
	int error = -ENOMEM, size, wsize;
	sd_serialize *work_area;
	char *filename = NULL;

	switch (option) {
	case OPTION_ADD:
		if (asprintf(&filename, "%s/.load", subdomainbase) == -1)
			goto exit;
		if (kernel_load) fd = open(filename, O_WRONLY);
		break;
	case OPTION_REPLACE:
		if (asprintf(&filename, "%s/.replace", subdomainbase) == -1)
			goto exit;
		if (kernel_load) fd = open(filename, O_WRONLY);
		break;
	case OPTION_REMOVE:
		if (asprintf(&filename, "%s/.remove", subdomainbase) == -1)
			goto exit;
		if (kernel_load) fd = open(filename, O_WRONLY);
		break;
	case OPTION_STDOUT:
		filename = strdup("stdout");
		fd = dup(1);
		break;
	case OPTION_OFILE:
		fd = dup(fileno(ofile));
		break;
	default:
		error = -EINVAL;
		goto exit;
		break;
	}

	if (fd < 0 && (kernel_load || option == OPTION_OFILE || option == OPTION_STDOUT)) {
		PERROR(_("Unable to open %s - %s\n"), filename,
		       strerror(errno));
		error = -errno;
		goto exit;
	}

	error = 0;

	free(filename);

	if (option == OPTION_REMOVE) {
		char *name, *ns = NULL;
		int len = 0;

		if (profile_ns) {
			len += strlen(profile_ns) + 2;
			ns = profile_ns;
		} else if (prof->ns) {
			len += strlen(prof->ns) + 2;
			ns = prof->ns;
		}
		if (prof->parent) {
			name = (char *) malloc(strlen(prof->name) + 3 +
				      strlen(prof->parent->name) + len);
			if (!name) {
				PERROR(_("Memory Allocation Error: Unable to remove ^%s\n"), prof->name);
				error = -errno;
				goto exit;
			}
			if (ns)
				sprintf(name, ":%s:%s//%s", ns,
					prof->parent->name, prof->name);
			else
				sprintf(name, "%s//%s", prof->parent->name,
					prof->name);
		} else if (ns) {
			name = (char *) malloc(len + strlen(prof->name) + 1);
			if (!name) {
				PERROR(_("Memory Allocation Error: Unable to remove %s:%s."), ns, prof->name);
				error = -errno;
				goto exit;
			}
			sprintf(name, ":%s:%s", ns, prof->name);
		} else {
			name = prof->name;
		}
		size = strlen(name) + 1;
		if (kernel_load) {
			wsize = write(fd, name, size);
			if (wsize < 0)
				error = -errno;
		}
		if (prof->parent || ns)
			free(name);
	} else {

		work_area = alloc_sd_serial();
		if (!work_area) {
			close(fd);
			PERROR(_("unable to create work area\n"));
			error = -ENOMEM;
			goto exit;
		}

		if (!sd_serialize_top_profile(work_area, prof)) {
			close(fd);
			free_sd_serial(work_area);
			PERROR(_("unable to serialize profile %s\n"),
			       prof->name);
			goto exit;
		}

		size = (long) (work_area->pos) - (long)(work_area->buffer);
		if (kernel_load || option == OPTION_STDOUT || option == OPTION_OFILE) {
			wsize = write(fd, work_area->buffer, size);
			if (wsize < 0) {
				error = -errno;
			} else if (wsize < size) {
				PERROR(_("%s: Unable to write entire profile entry\n"),
				       progname);
				error = -EIO;
			}
		}
		if (cache_fd != -1) {
			wsize = write(cache_fd, work_area->buffer, size);
			if (wsize < 0) {
				error = -errno;
			} else if (wsize < size) {
				PERROR(_("%s: Unable to write entire profile entry to cache\n"),
				       progname);
				error = -EIO;
			}
		}
		free_sd_serial(work_area);
	}

	close(fd);

	if (!prof->hat_table.empty() && option != OPTION_REMOVE) {
		if (load_flattened_hats(prof, option) == 0)
			return 0;
	}


exit:
	return error;
}

/* bleah the kernel should just loop and do multiple load, but to support
 * older systems we need to do this
 */
#define PROFILE_HEADER_SIZE
static char header_version[] = "\x04\x08\x00version";

static char *next_profile_buffer(char *buffer, int size)
{
	char *b = buffer;

	for (; size - sizeof(header_version); b++, size--) {
		if (memcmp(b, header_version, sizeof(header_version)) == 0) {
			return b;
		}
	}
	return NULL;
}

int sd_load_buffer(int option, char *buffer, int size)
{
	int fd = -1;
	int error = -ENOMEM, wsize, bsize;
	char *filename = NULL;
	char *b;

	switch (option) {
	case OPTION_ADD:
		if (asprintf(&filename, "%s/.load", subdomainbase) == -1)
			goto exit;
		if (kernel_load) fd = open(filename, O_WRONLY);
		break;
	case OPTION_REPLACE:
		if (asprintf(&filename, "%s/.replace", subdomainbase) == -1)
			goto exit;
		if (kernel_load) fd = open(filename, O_WRONLY);
		break;
	default:
		error = -EINVAL;
		goto exit;
		break;
	}

	if (kernel_load && fd < 0) {
		PERROR(_("Unable to open %s - %s\n"), filename,
		       strerror(errno));
		error = -errno;
		goto exit;
	}

	error = 0;
	for (b = buffer; b ; b = next_profile_buffer(b + sizeof(header_version), bsize)) {
		bsize = size - (b - buffer);
		if (kernel_load) {
			wsize = write(fd, b, bsize);
			if (wsize < 0) {
				error = -errno;
			} else if (wsize < bsize) {
				PERROR(_("%s: Unable to write entire profile entry\n"),
				       progname);
			}
		}
	}
	if (kernel_load) close(fd);
exit:
	free(filename);
	return error;
}
