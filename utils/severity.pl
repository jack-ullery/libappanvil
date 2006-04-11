#!/usr/bin/perl -w
# ----------------------------------------------------------------------
#    PROPRIETARY DATA of IMMUNIX INC.
#    Copyright (c) 2004, 2005 IMMUNIX (All rights reserved)
#
#    This document contains trade secret data which is the property
#    of IMMUNIX Inc.  This document is submitted to recipient in
#    confidence. Information contained herein may not be used, copied
#    or disclosed in whole or in part except as permitted by written
#    agreement signed by an officer of IMMUNIX, Inc.
# ----------------------------------------------------------------------

# This is just a quick-n-dirty tester and demo; not intended for use by
# end users.

use strict;
use Immunix::Severity;

sub ranker {
	my $ob = shift;
	my ($resource, $mode) = @_;

	if (defined $mode) {
		print "$mode $resource " . $ob->rank($resource, $mode);
	} else {
		print "$resource " . $ob->rank($resource);
	}
	print "\n";
}

my ($ob);
$ob = Immunix::Severity->new;

$ob->init("/tmp/severity.db");

ranker($ob, "CAP_SYS_ADMIN");
ranker($ob, "CAP_SETUID");
ranker($ob, "CAP_MISSPELLED");
ranker($ob, "MISSPELLED");
ranker($ob, "/etc/passwd","rw");
ranker($ob, "/etc/passwd","w");
ranker($ob, "/etc/passwd","r");
ranker($ob, "/etc/nothere","r");


print "\n";
$ob->init("/tmp/severity.db", -1111);

ranker($ob, "CAP_SYS_ADMIN");
ranker($ob, "CAP_SETUID");
ranker($ob, "CAP_MISSPELLED");
ranker($ob, "MISSPELLED");
ranker($ob, "/etc/passwd","rw");
ranker($ob, "/etc/passwd","w");
ranker($ob, "/etc/passwd","r");
ranker($ob, "/etc/nothere","r");
