#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>

#define OPT_EXPECT		"--expect="
#define OPT_EXPECT_LEN		strlen(OPT_EXPECT)

#define OPT_LABEL		"--label="
#define OPT_LABEL_LEN		strlen(OPT_LABEL)

#define OPT_TYPE_DBUS		"--dbus="
#define OPT_TYPE_DBUS_LEN	strlen(OPT_TYPE_DBUS)

static char *progname = NULL;

void usage(void)
{
	fprintf(stderr, "Usage: %s --expect=EXPECTED --label=LABEL --CLASS=PERMS QUERY...\n\n",
		progname);
	fprintf(stderr, "  EXPECTED\tA comma separated list of allow, audit, and/or anything.\n");
	fprintf(stderr, "\t\t\"anything\" is a special keyword that matches any condition\n");
	fprintf(stderr, "\t\tand cannot be used with other keywords. Additionally,\n");
	fprintf(stderr, "\t\tEXPECTED can be empty to indicate neither, allow or audit,\n");
	fprintf(stderr, "\t\tin the results.\n");
	fprintf(stderr, "  LABEL\t\tThe AppArmor label to use in the query\n");
	fprintf(stderr, "  CLASS\t\tThe rule class and may consist of:\n");
	fprintf(stderr, "\t\t  dbus\n");
	fprintf(stderr, "  PERMS\t\tA comma separated list of permissions. Possibilities\n");
	fprintf(stderr, "\t\tfor the supported rule classes are:\n");
	fprintf(stderr, "\t\t  dbus: send,receive,bind\n");
	fprintf(stderr, "\t\tAdditionaly, PERMS can be empty to indicate an empty mask\n");
	exit(1);
}

static int parse_expected(int *should_allow, int *should_audit, char *expected)
{
	char *expect;

	*should_allow = *should_audit = 0;

	expect = strtok(expected, ",");
	while (expect) {
		if (!strcmp(expect, "allow")) {
			*should_allow = 1;
		} else if (!strcmp(expect, "audit")) {
			*should_audit = 1;
		} else if (!strcmp(expect, "anything")) {
			*should_allow = *should_audit = -1;
		} else {
			fprintf(stderr, "FAIL: unknown expect: %s\n", expect);
			return 1;
		}

		expect = strtok(NULL, ",");
	}

	return 0;
}

static int parse_dbus_perms(uint32_t *mask, char *perms)
{
	char *perm;

	*mask = 0;

	perm = strtok(perms, ",");
	while (perm) {
		if (!strcmp(perm, "send"))
			*mask |= AA_DBUS_SEND;
		else if (!strcmp(perm, "receive"))
			*mask |= AA_DBUS_RECEIVE;
		else if (!strcmp(perm, "bind"))
			*mask |= AA_DBUS_BIND;
		else {
			fprintf(stderr, "FAIL: unknown perm: %s\n", perm);
			return 1;
		}

		perm = strtok(NULL, ",");
	}

	return 0;
}

static ssize_t build_query(char **qstr, const char *label, int class,
			   int argc, char **argv)
{
	int size, label_size, i;
	char *buffer, *to;

	label_size = strlen(label);
	size = label_size + 1;
	for (i = 0; i < argc; i++) {
		if (argv[i])
			size += strlen(argv[i]);
	}

	buffer = malloc(size + argc + 1 + AA_QUERY_CMD_LABEL_SIZE);
	if (!buffer)
		return -1;

	to = buffer + AA_QUERY_CMD_LABEL_SIZE;
	strcpy(to, label);
	to += label_size;
	*(to)++ = '\0';
	*(to)++ = class;

	for (i = 0; i < argc; to++, i++) {
		char *arg = argv[i];

		if (!arg)
			arg = "";
		to = stpcpy(to, arg);
	}
	*qstr = buffer;

	/* don't include trailing \0 in size */
	return size + argc + AA_QUERY_CMD_LABEL_SIZE;
}

int main(int argc, char **argv)
{
	char *label, *class_str, *query;
	int class, should_allow, allowed, should_audit, audited, rc;
	uint32_t mask;
	ssize_t query_len;

	progname = argv[0];

	if (argc < 5)
		usage();

	if (!strncmp(argv[1], OPT_EXPECT, OPT_EXPECT_LEN)) {
		rc = parse_expected(&should_allow, &should_audit,
				    argv[1] + OPT_EXPECT_LEN);
		if (rc)
			usage();
	}

	if (!strncmp(argv[2], OPT_LABEL, OPT_LABEL_LEN))
		label = argv[2] + OPT_LABEL_LEN;
	else
		usage();

	class_str = argv[3];
	if (!strncmp(class_str, OPT_TYPE_DBUS, OPT_TYPE_DBUS_LEN)) {
		class = AA_CLASS_DBUS;
		rc = parse_dbus_perms(&mask, class_str + OPT_TYPE_DBUS_LEN);
		if (rc)
			usage();
	} else {
		fprintf(stderr, "FAIL: unknown rule class: %s\n", class_str);
		usage();
	}

	query_len = build_query(&query, label, class, argc - 4, argv + 4);
	if (query_len < 0) {
		fprintf(stderr, "FAIL: failed to allocate memory for query string\n");
		exit(1);
	}

	rc = aa_query_label(mask, query, query_len, &allowed, &audited);
	free(query);
	if (rc < 0) {
		fprintf(stderr, "FAIL: failed to perform query: %m\n");
		exit(1);
	}

	if ((should_allow == -1 && should_audit == -1) ||
	    (allowed == should_allow && audited == should_audit)) {
		printf("PASS\n");
	} else {
		fprintf(stderr, "FAIL: the access should %sbe allowed and should %sbe audited\n",
			allowed ? "" : "not ", audited ? "" : "not ");
		exit(1);
	}

	exit(0);
}
