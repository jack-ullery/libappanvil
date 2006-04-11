# $Id: $
# ------------------------------------------------------------------
#
#    Copyright (C) 2005-2006 Novell/SUSE
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

package Immunix::Reports;

################################################################################
# /usr/lib/perl5/site_perl/Reports.pm
#
#   - Parses /var/log/messages for SubDomain messages
#   - Writes results to .html or comma-delimited (.csv) files (Optional)
#
#  Requires:
#   Immunix::Events;
#   Time::Local (temporary)
#
#  Input (Optional):
#       -Start Date|End Date (Month, Day, Year, Time)
#       -Program Name
#       -Profile Name
#       -PID
#       -Denied Resources
#
################################################################################

use strict;
use Immunix::Ycp;				# debug
use DBI;
use DBD::SQLite;

use POSIX;
use Locale::gettext;

setlocale(LC_MESSAGES, "");
textdomain("Reports");

my $eventDb = '/var/log/apparmor/events.db';
my $numEvents = 1000;

sub month2Num {

    my $lexMon = shift;
    my $months = { "Jan" =>'01', "Feb"=>'02', "Mar"=>'03', "Apr"=>'04', "May"=>'05', "Jun"=>'06',
                    "Jul"=>'07', "Aug"=>'08', "Sep"=>'09', "Oct"=>'10',  "Nov"=>'11', "Dec"=>'12' };

    my $numMonth = $months->{$lexMon};

    return $numMonth;
}

sub num2Month {

    my $monthNum = shift;

    my @months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    my $lexMonth = $months[($monthNum -1)];

    return $lexMonth;
}

# Converts Epoch Time to Formatted Date String
sub getDate {

    my $epTime = shift;

    my $date = localtime($epTime);

    my ($day, $mon, $mondate, $time, $year) = split(/\s+/, $date);
    my ($hour,$min,$sec) = split(/:/, $time);

    $mon = month2Num($mon);

    # we want 2 digits for easier reading
    $mon = sprintf("%02d", $mon);
    $mondate = sprintf("%02d", $mondate);

    my $newDate = "$year-$mon-$mondate $time";
    return $newDate;
}

sub round {
    my $num = shift;
    $num = sprintf("%.2f", $num);
    return ("$num");
}


# round up
sub pageRound {

    my $num = shift;
    my $pnum = int($num);

    if ( $pnum < $num ) {
        $pnum++;
    }

    return $pnum;
}

sub checkFileExists {

	my $file = shift;

	if ( $file && -e $file ) {
		return 1;
	} else {
		return 0;
	}

}

# Translate mode & sdmode for parsing
sub rewriteModes {

	my $filts = shift;

    # Mode wrangling - Rewrite for better matches
    if ($filts->{'mode'} && $filts->{'mode'} ne "All") {

        my @mode = ();
        my $tmpMode = undef;

        @mode = split (//, $filts->{'mode'});

        if (@mode > 0) {
            $tmpMode = join("|", @mode);
        } else {
            delete($filts->{'mode'});
        }

        if ($tmpMode) {
            $filts->{'mode'} = $tmpMode;
        }

    }

	# Rewrite sdmode for more flexible matches
    if ($filts->{'sdmode'} && $filts->{'sdmode'} ne "All") {
        my @tmpMode = ();
        if ( $filts->{'sdmode'} =~ /[pP]/ ) { push(@tmpMode,'PERMIT'); }
        if ( $filts->{'sdmode'} =~ /[rR]/ ) { push(@tmpMode,'REJECT'); }
        if ( $filts->{'sdmode'} =~ /[aA]/ ) { push(@tmpMode,'AUDIT'); }
        if (@tmpMode > 0) {
            $filts->{'sdmode'} = join('|', @tmpMode);
        } else {
            delete($filts->{'sdmode'});
        }
    }

	return $filts;
}

sub enableEventD {
	# make sure the eventd is enabled before we do any reports
	my $need_enable = 0;
	if(open(SDCONF, "/etc/apparmor/subdomain.conf")) {
		while(<SDCONF>) {
			if(/^\s*APPARMOR_ENABLE_AAEVENTD\s*=\s*(\S+)\s*$/) {
				my $flag = lc($1);
				# strip quotes from the value if present
				$flag = $1 if $flag =~ /^"(\S+)"$/;
				$need_enable = 1 if $flag ne "yes";
			}
		}
		close(SDCONF);
	}

	# if the eventd isn't enabled, we'll turn it on the first time they
	# run a report and start it up - if something fails for some reason,
	# we should just fall through and the db check should correctly tell
	# the caller that the db isn't initialized correctly
	if($need_enable) {
		my $old = "/etc/apparmor/subdomain.conf";
		my $new = "/etc/apparmor/subdomain.conf.$$";
		if(open(SDCONF, $old)) {
			if(open(SDCONFNEW, ">$new")) {
				my $foundit = 0;

				while(<SDCONF>) {
					if(/^\s*APPARMOR_ENABLE_AAEVENTD\s*=/) {
						print SDCONFNEW "APPARMOR_ENABLE_AAEVENTD=\"yes\"\n";

						$foundit = 1;
					} else {
						print SDCONFNEW;
					}
				}

				unless($foundit) {
					print SDCONFNEW "APPARMOR_ENABLE_AAEVENTD=\"yes\"\n";
				}

				close(SDCONFNEW);

				# if we were able to overwrite the old config
				# config file with the new stuff, we'll kick
				# the init script to start up aa-eventd
				if(rename($new, $old)) {
					if(-e "/sbin/rcaaeventd") {
						system("/sbin/rcaaeventd restart >/dev/null 2>&1");
					} else {
						system("/sbin/rcapparmor restart >/dev/null 2>&1");
					}
				}
			} 
			close(SDCONF);
		}
		
	}

	return $need_enable;
}

# Check that events db exists and is populated
#	- Returns 1 for good db, 0 for bad db
sub checkEventDb {

	my $count = undef;
	my $eventDb = '/var/log/apparmor/events.db';

	# make sure the event daemon is enabled
	if(enableEventD()) {

		my $now = time;

		# wait until the event db appears or we hit 1 min
		while (! -e $eventDb) {
			sleep 2;	
			return 0 if ((time - $now) >= 60);
		}

		# wait until it stops changing or we hit 1 min - the event
		# daemon flushes events to the db every five seconds.
		my $last_modified = 0;
		my $modified = (stat($eventDb))[9];
		while($last_modified != $modified) {
			sleep 10;	
			last if ((time - $now) >= 60);
			$last_modified = $modified;
			$modified = (stat($eventDb))[9];
		}
	}

        my $query = "SELECT count(*) FROM events ";

        # Pull stuff from db
        my $dbh = DBI->connect("dbi:SQLite:dbname=$eventDb", "", "", {RaiseError => 1, AutoCommit => 1});

        eval {
            my $sth = $dbh->prepare($query);
            $sth->execute;
            $count =  $sth->fetchrow_array();

            $sth->finish;
        };

        if ( $@ ) {
            Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s."), $DBI::errstr));
            return;
        }

        $dbh->disconnect();


	if ( $count && $count > 0 ) {
		return 1;
	} else {
		return 0;
	}
}

# Called from ag_reports_parse
sub getNumPages {

    my $args = shift;
    my $db = ();
    my $numPages = 0;
    my $count = 0;
	my $type = undef;
    my $eventRep = "/var/log/apparmor/reports/events.rpt";

	# Figure out whether we want db count or file parse
	if ( $args->{'type'} )  {
		if ( $args->{'type'} eq 'sir' || $args->{'type'} eq 'ess-multi' ) {
			$type = 'db';
		} elsif ( $args->{'type'} eq 'ess') {
			return 1;			# ess reports have one page by definition
		} else {
			$type = 'arch';		# archived or file
		}
	}

    # Parse sdmode & mode labels
    if ( $args->{'sdmode'} ) {
        $args->{'sdmode'} =~ s/\&//g;
        $args->{'sdmode'} =~ s/\://g;
        $args->{'sdmode'} =~ s/\s//g;
        $args->{'sdmode'} =~ s/AccessType//g;

        if ($args->{'sdmode'} eq "All") {
            delete($args->{'sdmode'});
		}
    }

    if ( $args->{'mode'} ) {
        $args->{'mode'} =~ s/\&//g;
        $args->{'mode'} =~ s/Mode\://g;
        $args->{'mode'} =~ s/\s//g;

        if ($args->{'mode'} eq "All") {
            delete($args->{'mode'});
		}
    }
	########################################

	$args = rewriteModes($args); 

	if ( $type && $type eq 'db' ) {

		my $start = undef;	my $end = undef;

		if ( $args->{'startTime'} && $args->{'startTime'} > 0 ) {
			$start = $args->{'startTime'};
		}

		if ( $args->{'endTime'} && $args->{'endTime'} > 0 ) {
			$end = $args->{'endTime'};
		}

		my $query = "SELECT count(*) FROM events ";

        # We need filter information for getting a correct count 
        #my $filts = getSirFilters($args);					# these should be sent from YaST
		my $filts = undef;

		if ( $args->{'prog'} ) { $filts->{'prog'} = $args->{'prog'}; }
		if ( $args->{'profile'} ) { $filts->{'profile'} = $args->{'profile'}; }
		if ( $args->{'pid'} ) { $filts->{'pid'} = $args->{'pid'}; }
		if ( $args->{'resource'} ) { $filts->{'resource'} = $args->{'resource'}; }
		if ( $args->{'severity'} ) { $filts->{'severity'} = $args->{'severity'}; }
		if ( $args->{'sdmode'} ) { $filts->{'sdmode'} = $args->{'sdmode'}; }
		if ( $args->{'mode'} ) { $filts->{'mode'} = $args->{'mode'}; }

		for(sort(keys(%$filts))) { 
			if ( $filts->{$_} eq '-' || $filts->{$_} eq 'All' ) {
				delete( $filts->{$_});
			}
		}

		my $midQuery = getQueryFilters($filts,$start,$end);

		$query .= "$midQuery";

		# Pull stuff from db
		my $dbh = DBI->connect("dbi:SQLite:dbname=$eventDb", "", "", {RaiseError => 1, AutoCommit => 1});

		eval {
			my $sth = $dbh->prepare($query);
			$sth->execute;
			$count =  $sth->fetchrow_array();

			$sth->finish;
		};

		if ( $@ ) {
            Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s."), $DBI::errstr));
	        return;
	    }

	    $dbh->disconnect();

		#Immunix::Ycp::y2milestone("Numpages Query: $query");		# debug

		$numPages = pageRound($count/$numEvents);
		if ( $numPages < 1 ) { $numPages = 1; }

	} elsif ( $type &&  $type eq 'arch' ) {

	    if ( open(REP, "<$eventRep") ) {

	        while(<REP>) {
	            if (/^Page/) {
	                $numPages++;
	            } else {
					$count++;
				}
	        }

	        close REP;

	    } else {
            Immunix::Ycp::y2error(sprintf(gettext("Couldn't open file: %s."), $eventRep));
	    }

	} else {
        Immunix::Ycp::y2error(gettext("No type value passed.  Unable to determine page count."));
		return("1");
	}

	if ( $numPages < 1 ) { $numPages = 1; }

	my $numCheck = int($count/$numEvents);

	if ($numPages < $numCheck) {
		$numPages = $numCheck;
	} 

    return($numPages);
}

sub getEpochFromNum {

    my $date = shift;
	my $place = shift || undef;			# Used to set default $sec if undef

    my ($numMonth,$numDay,$time,$year) = split(/\s+/, $date);
    my ($hour,$min,$sec) = '0';
	my $junk = undef;

	if ($time =~ /:/) {
		($hour,$min,$sec,$junk) = split(/\:/, $time);
		if (! $hour || $hour eq "" )  { $hour = '0'; }
		if (! $min || $min eq "" )  { $min = '0'; }
		if (! $sec || $sec eq "" )  { 
			if ($place eq 'end') {
				$sec = '59'; 
			} else {
				$sec = '0'; 
			}
		}
	} 

    $numMonth--;    # Months start from 0 for epoch translation

    if (! $year) { $year = (split(/\s+/, localtime))[4]; }
    my $epochDate = timelocal($sec,$min,$hour,$numDay,$numMonth,$year);

    return $epochDate;
}

sub getEpochFromStr {

    my $lexDate = shift;

    my ($lexMonth, $dateDay, $fullTime, $year) = split(/\s+/, $lexDate);
    #my ($lexDay, $lexMonth, $dateDay, $fullTime, $year) = split(/\s+/, $lexDate);
    my ($hour,$min,$sec) = split(/\:/, $fullTime);

    if (! $year) { $year = (split(/\s+/, localtime))[4]; }

    my $numMonth = month2Num($lexMonth);

    my $epochDate = timelocal($sec,$min,$hour,$dateDay,$numMonth,$year);

    return $epochDate;
}

# Replaces old files with new files
sub updateFiles {

    my ( $oldFile, $newFile )  = @_;

    if ( unlink("$oldFile") ) {
        if ( ! rename ("$newFile", "$oldFile") ) {
            if ( ! system('/bin/mv', "$newFile","$oldFile") ) {
                Immunix::Ycp::y2error(sprintf(gettext("Failed copying %s."), $oldFile));
                return 1;
            }
        }
    } else {
        system('/bin/rm', "$oldFile");
        system('/bin/mv', "$newFile", "$oldFile");
    }

    return 0;
}

# This is a holder, that was originally part of exportLog()
# Used by /usr/bin/reportgen.pl
sub exportFormattedText {

	my ($repName,$logFile,$db) = @_;

	my $date = localtime;
	open (LOG, ">$logFile") || die "Couldn't open $logFile";

        # Date Profile PID Mesg
		print LOG "$repName: Log generated by Novell AppArmor, $date\n\n";
		printf LOG "%-21s%-32s%-8s%-51s", "Host","Date","Program","Profile","PID","Severity","Mode","Detail","Access Type";
		print LOG "\n";

		for (sort (@$db) ) {
			print LOG "$_->{'host'},$_->{'time'},$_->{'prog'},$_->{'profile'},";
			print LOG "$_->{'pid'},$_->{'severity'},$->{'mode'},$_->{'resource'},$_->{'sdmode'}\n";
		}


	close LOG;
}

sub exportLog {

	my ($exportLog,$db,$header) = @_;

    if ( open (LOG, ">$exportLog") ) {

		my $date = localtime();

		if ($exportLog =~ /csv/ ) {

			# $header comes from reportgen.pl (scheduled reports)
			if ($header) { print LOG "$header\n\n"; } 

			for (@$db) {
		        no strict;

				# host time prog profile pid severity resource sdmode mode
		        #print LOG "$_->{'host'},$_->{'time'},$_->{'prog'},$_->{'profile'},$_->{'pid'},";
		        print LOG "$_->{'host'},$_->{'date'},$_->{'prog'},$_->{'profile'},$_->{'pid'},";
				print LOG "$_->{'severity'},$_->{'mode'},$_->{'resource'},$_->{'sdmode'}\n";

			}

		} elsif ( $exportLog =~ /html/ ) {

			print LOG "<html><body bgcolor='fffeec'>\n\n";
			print LOG "<font face='Helvetica,Arial,Sans-Serif'>\n";

			# $header comes from reportgen.pl (scheduled reports)
			if ($header) {
				print LOG "$header\n\n";
			} else {
				print LOG "<br><h3>$exportLog</h3><br>\n<h4>Log generated by Novell AppArmor, $date</h4>\n\n";
			}

			print LOG "<hr><br><table border='1' cellpadding='2'>\n";
			#print LOG "<tr bgcolor='edefff'><th>Date</th><th>Profile</th><th>PID</th><th>Message</th></tr>\n";
			print LOG "<tr bgcolor='edefff'><th>Host</th><th>Date</th><th>Program</th><th>Profile</th><th>PID</th>" .
						"<th>Severity</th><th>Mode</th><th>Detail</th><th>Access Type</th></tr>\n";

			my $idx = 1;

			for (@$db) {
		        no strict;
				$idx++;
				if ( $idx%2 == 0 ) {

							#"<td>&nbsp;$_->{'time'}&nbsp;</td>" .
					print LOG "<tr><td>&nbsp;$_->{'host'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'date'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'prog'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'profile'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'pid'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'severity'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'mode'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'resource'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'sdmode'}&nbsp;</td></tr>\n";

				} else {
					# Shade every other row
					print LOG "<tr='edefef'><td>&nbsp;$_->{'host'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'date'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'prog'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'profile'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'pid'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'severity'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'mode'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'resource'}&nbsp;</td>" .
							"<td>&nbsp;$_->{'sdmode'}&nbsp;</td></tr>\n";

				}
	        }

			print LOG "<br></table></font></body></html>\n\n";
		}

        close LOG;
    } else {
        Immunix::Ycp::y2error(sprintf(gettext("Export Log Error: Couldn't open %s"), $exportLog));
    }
	# return($error);
}

# Pulls info on single report from apparmor xml file
sub getXmlReport {

	my ($repName,$repConf) = @_;
	my $repFlag = 0;

    my %rep = ();

    if ( defined($repName) && ref($repName) ) {

        if ( $repName->{'base'} ) {
            $repName = $repName->{'base'};
        } elsif ( $repName->{'name'} ) {
            $repName = $repName->{'name'};
        }

    }

    if ( ! $repName ) {
        Immunix::Ycp::y2error(gettext("Fatal error.  No report name given. Exiting."));
    }

	if ( ! $repConf || ! -e $repConf ) {
		$repConf = '/etc/apparmor/reports.conf';
		if ( ! -e $repConf ) {
            Immunix::Ycp::y2error(sprintf(gettext("Unable to get configuration info for %s.
                Unable to find %s."), $repName, $repConf));
			exit 1;
		}
	}

    if ( open(XML, "<$repConf") ) {

        while(<XML>) {

				chomp;

                if ( /\<name\>/ ) {
					#my $name = (split(/\"/, $_))[1];
					/\<name\>(.+)\<\/name\>/;
					my $name = $1;
					if ( $name eq $repName ) {
	                    $rep{'name'} = $name; 
						$repFlag = 1;
					}

				} elsif ( /\<\/report\>/ ) {

					$repFlag = 0;

				} elsif ( $repFlag == 1 ) { 
                    if ( /\s*\<\w+\s+(.*)\/\>.*$/  ) {
                      my $attrs = $1;
                      chomp($attrs);
                      my @attrlist = split(/\s+/, $attrs);
                      for ( @attrlist ) {
                        #Match attributes
                        if ( /\s*(\S+)=\"(\S+)\"/ ) {
                          $rep{$1} = $2 unless $2 eq '-';  
                        } 
                      }
					} elsif ( /\<(\w+)\>([\w+|\/].*)\<\// ) {

	                    if ($1) {
							$rep{"$1"}= $2 unless $2 eq '-';
						} else {
							Immunix::Ycp::y2error(sprintf(gettext("Failed to parse: %s."), $_));
						}
	                }
				}
        }

        close XML;

    } else {
		Immunix::Ycp::y2error(sprintf(gettext("Fatal Error.  Couldn't open %s."), $repConf));
        exit 1;
    }

    return \%rep;
}

# Returns info on currently confined processes
sub getCfInfo {

    my $ref = ();
    my @cfDb = ();

    my $cfApp = '/usr/sbin/unconfined';

    if ( open (CF, "$cfApp |") ) {

        my $host = `hostname`;
        chomp($host);

        my $date = localtime;

        while(<CF>) {

            my $ref = ();
            my $all = undef;
            $ref->{'host'} = $host;
            $ref->{'date'} = $date;
            chomp;

            ($ref->{'pid'}, $ref->{'prog'}, $all) = split(/\s+/, $_, 3);
            $all = /\s*((not)*\s*confined\s*(by)*)/;
            $ref->{'state'} = $1;
            $ref->{'state'} =~ s/\s*by//g;
            $ref->{'state'} =~ s/not\s+/not-/g;
            ($ref->{'prof'}, $ref->{'type'}) = split(/\s+/, $_);

            if ( $ref->{'prog'} eq "") { $ref->{'prog'} = "-"; }
            if ( $ref->{'prof'} eq "") { $ref->{'prof'} = "-"; }
            if ( $ref->{'pid'} eq "") { $ref->{'pid'} = "-"; }
            if ( $ref->{'state'} eq "") { $ref->{'state'} = "-"; }
            if ( $ref->{'type'} eq "") { $ref->{'type'} = "-"; }

            push (@cfDb, $ref);
        }
        close CF;

    } else {
        my $error = sprintf(gettext("Fatal Error.  Can't run %s.  Exiting."), $cfApp);
        Immunix::Ycp::y2error($error);
        return $error;
    }

    return (\@cfDb);
}

# generate stats for ESS reports
sub getEssStats {

	my $args = shift;

    #my ($host, $targetDir, $startdate, $enddate) = @_;

    my @hostDb = ();
    my @hostList = ();
	my $targetDir = undef;
	my $host = undef;
	my $startdate = undef;
	my $enddate = undef;

    if ( ! $args->{'targetDir'} ) {
        $targetDir = '/var/log/apparmor/';
    }

	if ( $args->{'host'} ) { $host = $args->{'host'}; }

	if ( $args->{'startdate'} ) {
		$startdate = $args->{'startdate'};
	} else {
    	$startdate = '1104566401';		# Jan 1, 2005
	}

	if ( $args->{'enddate'} ) {
		$enddate = $args->{'enddate'};
	} else {
	    $enddate = time;
	}

    if ( ! -e $targetDir ) {
        Immunix::Ycp::y2error(sprintf(gettext("Fatal Error.  No directory, %s, found.  Exiting."), $targetDir));
        return;
    }

    # Max Sev, Ave. Sev, Num. Rejects, Start Time, End Time
    my $ctQuery = "SELECT count(*) FROM events WHERE time >= $startdate AND time <= $enddate";

    my $query = "SELECT MAX(severity), AVG(severity), COUNT(id), MIN(time), " .
                "MAX(time) FROM events WHERE sdmode='REJECTING' AND " .
                "time >= $startdate AND time <= $enddate";
#                "MAX(time) FROM events join info WHERE sdmode='REJECTING' AND " .

    # Get list of hosts to scan
    if ( opendir (TDIR, $targetDir) ) {

        @hostList = grep(/\.db/, readdir(TDIR));
        close TDIR;

    } else {
        Immunix::Ycp::y2error(sprintf(gettext("Fatal Error.  Couldn't open %s.  Exiting"), $targetDir));
        return;
    }

    # Cycle through for each host
    for my $eventDb (@hostList) {

        $eventDb = "$targetDir/$eventDb";

        my $ess = undef;
        my $ret = undef;
        my $count = undef;
        #my $eventDb = '/var/log/apparmor/events.db';

        my $dbh = DBI->connect("dbi:SQLite:dbname=$eventDb", "", "", {RaiseError => 1, AutoCommit => 1});

        # get hostname
        my $host = undef;
        my $hostQuery = "SELECT * FROM info WHERE name='host'";

        eval {
            my $sth = $dbh->prepare($hostQuery);
            $sth->execute;
            $host =  $sth->fetchrow_array();
            $sth->finish;
        };

        if ( $@ ) {
            Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s"), $DBI::errstr));
            return;
        }

        # Get number of events
        eval {
            my $sth = $dbh->prepare($ctQuery);
            $sth->execute;
            $count =  $sth->fetchrow_array();
            $sth->finish;
        };

        if ( $@ ) {
            Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s"), $DBI::errstr));
            return;
        }

        # Get rest of stats 
        eval {
            $ret = $dbh->selectall_arrayref("$query");
        };

        if ( $@ ) {
            Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s"), $DBI::errstr));
            return;
        }

        $dbh->disconnect();

        # hostIp, startDate, endDate, sevHi,  sevMean, numRejects
        if ( $host ) {
            $ess->{'host'} = $host; 
        } else {
            $ess->{'host'} = '';
        }

        $ess->{'sevHi'} = $$ret[0]->[0]; 

        if ( ! $ess->{'sevHi'} ) { 
            $ess->{'sevHi'} = 0;
        }

        $ess->{'sevMean'} = $$ret[0]->[1]; 

        if ( ! $ess->{'sevMean'} || $ess->{'sevHi'} == 0) { 
            $ess->{'sevMean'} = 0;
        } else {
            $ess->{'sevMean'} = round("$ess->{'sevMean'}"); 
        }

        $ess->{'numRejects'} = $$ret[0]->[2]; 
        $ess->{'startdate'} = $$ret[0]->[3]; 
        $ess->{'enddate'} = $$ret[0]->[4]; 
        $ess->{'numEvents'} = $count;

        # Convert dates
        if ( $ess->{'startdate'} && $ess->{'startdate'} !~ /:/) {
            $ess->{'startdate'} = Immunix::Reports::getDate($ess->{'startdate'});
        }
        if ( $ess->{'enddate'} && $ess->{'enddate'} !~ /:/) {
            $ess->{'enddate'} = Immunix::Reports::getDate($ess->{'enddate'});
        }

        push (@hostDb, $ess);
    }

    return \@hostDb;
}


# get ESS stats for archived reports (warning -- this can be slow for large files 
# debug -- not fully functional yet
sub getArchEssStats {

	my $args = shift;

	my $prevTime = '0';
	my $prevDate = '0';
	my $startDate = '1104566401';		# Jan 1, 2005
	my $endDate =  time; 

	if ($args->{'startdate'} ) { $startDate = $args->{'startdate'}; }
	if ($args->{'enddate'} )   { $endDate   = $args->{'enddate'}; }

	# hostIp, startDate, endDate, sevHi,  sevMean, numRejects
    my @eventDb = getEvents("$startDate","$endDate");

	my @hostIdx = ();			# Simple index to all hosts for quick host matching
	my @hostDb = ();			# Host-keyed Data for doing REJECT stats

	# Outer Loop for Raw Event db
	for (@eventDb) {

		if ( $_->{'host'} ) {

			my $ev = $_;		# current event record

			# Create new host entry, or add to existing
			if ( grep(/$ev->{'host'}/, @hostIdx) == 1 ) {

				# Inner loop, but the number of hosts should be small
				for (@hostDb) {

					if ($_->{'host'} eq $ev->{'host'}) {

						if ( $_->{'startdate'} > $ev->{'date'} ) {
							$_->{'startdate'} = $ev->{'date'};			# Find earliest start date
						}

						$_->{'numEvents'}++;			# tally all events reported for host

						if ( $ev->{'sdmode'} ) {
							if ( $ev->{'sdmode'} =~ /PERMIT/ ) { $_->{'numPermits'}++; }
							if ( $ev->{'sdmode'} =~ /REJECT/ ) { $_->{'numRejects'}++; }
							if ( $ev->{'sdmode'} =~ /AUDIT/ ) { $_->{'numAudits'}++; }
						}

						# Add stats to host entry
						#if ( $ev->{'severity'} && $ev->{'severity'} =~ /\b\d+\b/ ) {}
						if ( $ev->{'severity'} && $ev->{'severity'} != -1 ) {

							$_->{'sevNum'}++;
							$_->{'sevTotal'} = $_->{'sevTotal'} +  $ev->{'severity'};

							if ($ev->{'severity'} > $_->{'sevHi'} ) {
								$_->{'sevHi'} = $ev->{'severity'};
							}
						} else {
							$_->{'unknown'}++;
						}
					}
				}

			} else {

				# New host
				my $rec = undef;
				push(@hostIdx,$ev->{'host'});	# Add host entry to index

				$rec->{'host'} = $ev->{'host'};
				$rec->{'startdate'} = $startDate;
				#$rec->{'startdate'} = $ev->{'date'};

				if ( $endDate ) {
					$rec->{'enddate'} = $endDate; 
				} else {
					$rec->{'enddate'} = time; 
				}

				# Add stats to host entry
				if ( $ev->{'sev'} && $ev->{'sev'} ne "U" ) {
			
					$rec->{'sevHi'} = $ev->{'sev'};
					$rec->{'sevTotal'} = $ev->{'sev'};
					$rec->{'sevNum'} = 1;
					$rec->{'unknown'} = 0;

				} else {
					$rec->{'sevHi'} = 0; 
					$rec->{'sevTotal'} = 0;
					$rec->{'sevNum'} = 0;
					$rec->{'unknown'} = 1;
				}

				# Start sdmode stats
				$rec->{'numPermits'} = 0;
				$rec->{'numRejects'} = 0;
				$rec->{'numAudits'}  = 0;
				$rec->{'numEvents'}  = 1;			# tally all events reported for host

				if ( $ev->{'sdmode'} ) {
					if ( $ev->{'sdmode'} =~ /PERMIT/ ) { $rec->{'numPermits'}++; }
					if ( $ev->{'sdmode'} =~ /REJECT/ ) { $rec->{'numRejects'}++; }
					if ( $ev->{'sdmode'} =~ /AUDIT/ ) { $rec->{'numAudits'}++; }
				}

				push (@hostDb,$rec);			# Add new records to host data list
			}

		} else {
			next;		# Missing host info -- big problem
		}
	}					# END @eventDb loop

	# Process simple REJECT-related stats (for Executive Security Summaries)
	for ( @hostDb ) {

		# In the end, we want this info:
		#	- Hostname, Startdate, Enddate, # Events, # Rejects, Ave. Severity, High Severity

		if ( $_->{'sevTotal'} > 0 && $_->{'sevNum'} > 0 ) {
			$_->{'sevMean'} = round($_->{'sevTotal'}/$_->{'sevNum'});
		} else {
			$_->{'sevMean'} = 0;
		}

		# Convert dates
		if ($_->{'startdate'} !~ /:/) {$_->{'startdate'} = getDate($startDate); }
		if ($_->{'enddate'} !~ /:/) { $_->{'enddate'} = getDate($_->{'enddate'}); }

		# Delete stuff that we may use in later versions (YaST is a silly, silly data handler)
		delete($_->{'sevTotal'});
		delete($_->{'sevNum'});
		delete($_->{'numPermits'});
		delete($_->{'numAudits'});
		delete($_->{'unknown'});

	}

	return(\@hostDb);
}

# special version of getEvents() for /usr/bin/reportgen.pl
sub grabEvents {

	my ($rep,$start,$end) = @_;
	my $db = undef;
	my $prevDate = "0";
	my $prevTime = "0";

	my $query = "SELECT * FROM events ";

    # Clear unnecessary filters
	if ( $rep->{'prog'} ) { $rep->{'prog'} =~ s/\s+//g; }
	if ( $rep->{'prof'} ) { $rep->{'prof'} =~ s/\s+//g; }
	if ( $rep->{'mode'} ) { $rep->{'mode'} =~ s/\s+//g; }
	if ( $rep->{'sdmode'} ) { $rep->{'sdmode'} =~ s/\s+//g; }
	if ( $rep->{'sev'} ) { $rep->{'sev'} =~ s/\s+//g; }
	if ( $rep->{'res'} ) { $rep->{'res'} =~ s/\s+//g; }

    if ($rep->{'prog'} && ($rep->{'prog'} eq "-" || $rep->{'prog'} eq "All") ) {
        delete($rep->{'prog'});
    }
    if ($rep->{'prof'} && $rep->{'prof'} eq "-") { delete($rep->{'prof'}); }
    if ($rep->{'pid'} && $rep->{'pid'} eq "-") { delete($rep->{'pid'}); }
    if ( $rep->{'sev'} && ( $rep->{'sev'} eq "-" || $rep->{'sev'} eq "All" ) ) {
		delete($rep->{'sev'});
	}
    if ($rep->{'resource'} && $rep->{'resource'} eq "-") { delete($rep->{'resource'}); }

    if ($rep->{'mode'} && ( $rep->{'mode'} eq "-" || $rep->{'mode'} eq "All" ) ) {
        delete($rep->{'mode'});
    }

    if ($rep->{'sdmode'} && ($rep->{'sdmode'} eq "-" || $rep->{'sdmode'} eq "All") ) {
        delete($rep->{'sdmode'});
    }

	$rep = rewriteModes($rep);

	# Set Dates far enough apart to get all entries (ie. no date filter)
	my $startDate = '1104566401';			# Jan 1, 2005
	my $endDate = time;

	if ( $start && $start > 0 ) { $startDate = $start; }

    if ( ref($rep) ) {
        my $midQuery = getQueryFilters($rep,$startDate,$endDate);
        $query .= "$midQuery";
    }

	$db = getEvents($query,"$startDate","$endDate");

	return($db);
}

sub getQueryFilters {

	my ($filts,$start,$end) = @_;

	my $query = undef; 
	my $wFlag = 0;

	if ( $filts ) {

        # Match any requested filters or drop record
        ############################################################
        if ( $filts->{'prog'} ) {
			$query .= "WHERE events.prog = \'$filts->{'prog'}\' ";
			$wFlag = 1;
        } 

        if ( $filts->{'profile'} && $_->{'profile'} ) {
			if ( $wFlag == 1 ) {
				$query .= "AND events.profile = \'$filts->{'profile'}\' ";
			} else {
				$query .= "WHERE events.profile = \'$filts->{'profile'}\' ";
			}
			$wFlag = 1;
		}

        if ( $filts->{'pid'} ) {
			if ( $wFlag == 1 ) {
				$query .= "AND events.pid = \'$filts->{'pid'}\' ";
			} else {
				$query .= "WHERE events.pid = \'$filts->{'pid'}\' ";
			}
			$wFlag = 1;
		}

        if ($filts->{'severity'}) {
            if ($filts->{'severity'} eq "-" || $filts->{'severity'} eq "All" ) {
                delete($filts->{'severity'});
			} elsif ( $filts->{'severity'} eq "-1" || $filts->{'severity'} eq "U" ) {
				if ( $wFlag == 1 ) {
					$query .= "AND events.severity = '-1' ";
				} else {
					$query .= "WHERE events.severity = '-1' ";
				}
				$wFlag = 1;
            } else {
				if ( $wFlag == 1 ) {
					$query .= "AND events.severity >= \'$filts->{'severity'}\' ";
				} else {
					$query .= "WHERE events.severity >= \'$filts->{'severity'}\' ";
				}
				$wFlag = 1;
			}
        }

        if ( $filts->{'resource'} ) {
			if ( $wFlag == 1 ) {
				$query .= "AND events.resource LIKE '%$filts->{'resource'}%' ";
			} else {
				$query .= "WHERE events.resource LIKE '%$filts->{'resource'}%' ";
			}
			$wFlag = 1;
        }

        if ( $filts->{'mode'} ) {
			if ( $wFlag == 1 ) {
				$query .= "AND events.mode LIKE '%$filts->{'mode'}%' ";
			} else {
				$query .= "WHERE events.mode LIKE '%$filts->{'mode'}%' ";
			}
			$wFlag = 1;
        }

        if ( $filts->{'sdmode'} ) {

            if ( $filts->{'sdmode'} =~ /\|/ ) {

                my @sdmunge = split(/\|/, $filts->{'sdmode'});
                for (@sdmunge) { $_ = "\'\%" . "$_" . "\%\'"; }

                $filts->{'sdmode'} = join( " OR events.sdmode LIKE ", @sdmunge);

            } else {
                $filts->{'sdmode'} = "\'\%" . "$filts->{'sdmode'}" . "\%\'";
			}

            if ( $wFlag == 1 ) {
                $query .= "AND events.sdmode LIKE $filts->{'sdmode'} ";
            } else {
                $query .= "WHERE events.sdmode LIKE $filts->{'sdmode'} ";
            }
            $wFlag = 1;

        }
	}

	if ( $start && $start =~ /\d+/ && $start > 0 ) {
            if ( $wFlag == 1 ) {
                $query .= "AND events.time >= $start ";
            } else {
                $query .= "WHERE events.time >= $start ";
            }
			$wFlag = 1;
	}

	if ( $end && $end =~ /\d+/ && $end > $start ) {
            if ( $wFlag == 1 ) {
                $query .= "AND events.time <= $end ";
            } else {
                $query .= "WHERE events.time <= $end ";
            }
	}

	return $query;
}


sub getQuery {

	my ($filts,$page,$sortKey,$numEvents) = @_;

	if ( ! $page || $page < 1 || $page !~ /\d+/ ) { $page = 1; }
	if ( ! $sortKey ) { $sortKey = 'time'; }
	if ( ! $numEvents ) { $numEvents = '1000'; }

	my $limit = ( ($page * $numEvents) - $numEvents );

    my $query = "SELECT * FROM events ";

	if ( $filts ) {
		my $midQuery = getQueryFilters($filts);
		$query .= "$midQuery";
	}

    # Finish query
    $query .= "Order by $sortKey LIMIT $limit,$numEvents";

	return $query;
}

# - This should exec AFTER the initial select (should limit the number of records 
#   that we'll be mangling
# - There may be a way to do this with a creative query statement generator

sub queryPostProcess {

	my $db = shift;
	my @newDb = ();
	my $prevTime = 0;
	my $prevDate = 0;

	for (@$db) {

       # Shuffle special events into appropriate column variables
       ############################################################
       if ( $_->{'attrch'} ) { $_->{'sdmode'} .= " $_->{'attrch'}"; }

       if ( $_->{'type'} ) {

            if ( $_->{'type'} eq 'control_variable' ) {
                # OWLSM gets special treatment
                if ( $_->{'variable'} eq 'owlsm' ) {
                    #if ( $_->{'value'} ) {}
                    if ( $_->{'value'} == '0' ) {
                        $_->{'resource'} = "GLOBAL MODULE CHANGE: OWLSM DISABLED";
                    } elsif ( $_->{'value'} == '1' ) {
                        $_->{'resource'} = "GLOBAL MODULE CHANGE: OWLSM ENABLED";
                    } else {
                        $_->{'resource'} = "Unrecognized OWLSM activity.";
                    }
                } else {
                    $_->{'resource'} = "$_->{'variable'}";
                }
            } elsif ( $_->{'type'} eq 'capability' ) {
                $_->{'resource'} .= " $_->{'capability'}";

            } elsif ( $_->{'type'} eq 'attribute_change' ) {
                $_->{'sdmode'} .= " $_->{'attribute'} change";
            } elsif ( $_->{'type'} eq 'subdomain_insmod' ) {
                $_->{'resource'} = "AppArmor Started";
            } elsif ( $_->{'type'} eq 'subdomain_rmmod' ) {
                $_->{'resource'} = "AppArmor Stopped";
            # DROP logprof-hints
            } elsif ( $_->{'type'} eq 'unknown_hat' ) {
                next;
            # DROP logprof-hints
            } elsif ( $_->{'type'} eq 'changing_profile' ) {
                next;
            # DROP logprof-hints
            } elsif ( $_->{'type'} eq 'fork' ) {
                next;
            } elsif ( $_->{'type'} ne 'path' ) {
                $_->{'resource'} .= " $_->{'type'}";
            }
        }

        # Convert Epoch Time to Date
        if ( $_->{'time'} && $_->{'time'} == $prevTime ) {
            $_->{'date'} = $prevDate;
        } elsif ($_->{'time'}) {
            my $newDate = getDate("$_->{'time'}");
            $_->{'date'} = $newDate;
            $prevDate = $newDate;
            $prevTime = $_->{'time'};
        } else {
            $_->{'date'} = "0000-00-00 00:00:00";
        }
        # $_->{'time'} = undef;         # Don't need 'time', only 'date'
        if (! $_->{'host'}) { $_->{'host'} = "-"; }
        if (! $_->{'date'}) { $_->{'date'} = "-"; }
        if (! $_->{'prog'}) { $_->{'prog'} = "-"; }
        if (! $_->{'profile'}) { $_->{'profile'} = "-"; }
        if (! $_->{'pid'}) { $_->{'pid'} = "-"; }
        if (! $_->{'mode'}) { $_->{'mode'} = "-"; }
        if (! $_->{'resource'}) { $_->{'resource'} = "-"; }
        if (! $_->{'sdmode'}) { $_->{'sdmode'} = "-"; }

        if (! $_->{'severity'}) {
            $_->{'severity'} = "-";
        } elsif ($_->{'severity'} eq "-1") {
            $_->{'severity'} = "U";
        }# else {
        #   $_->{'severity'} = sprintf("%02d", $_->{'severity'});
        #}

        push(@newDb, $_);                  # Don't quote the $_ (breaks hash)

	}

	return \@newDb;

}

# Creates single hashref for the various filters 
sub setFormFilters {

    my $args = shift;
    my $filts = undef;

    if ( $args ) {

        if ( $args->{'prog'} ) { $filts->{'prog'} = $args->{'prog'}; }
        if ( $args->{'profile'} ) { $filts->{'profile'} = $args->{'profile'}; }
        if ( $args->{'pid'} ) { $filts->{'pid'} = $args->{'pid'}; }
        if ( $args->{'resource'} ) { $filts->{'resource'} = $args->{'resource'}; }
        if ( $args->{'severity'} ) { $filts->{'severity'} = $args->{'severity'}; }
        if ( $args->{'sdmode'} ) { $filts->{'sdmode'} = $args->{'sdmode'}; }
        if ( $args->{'mode'} ) { $filts->{'mode'} = $args->{'mode'}; }

    }

    return $filts;
}

# helper for getSirFilters()
# Makes gui-centric filters querying-friendly 
sub rewriteFilters {

	my $filts = shift;

    # Clear unnecessary filters
	for (keys(%$filts)) { if ( $filts->{$_} eq "All" ) { delete($filts->{$_}); } }

    if ($filts->{'prog'} && ($filts->{'prog'} eq "-" || $filts->{'prog'} eq "All") ) {
        delete($filts->{'prog'});
    }
    if ($filts->{'profile'} && ($filts->{'profile'} eq "-") ) { delete($filts->{'profile'}); }
    if ($filts->{'pid'} && ($filts->{'pid'} eq "-") ) { delete($filts->{'pid'}); }
    if ($filts->{'severity'} && ($filts->{'severity'} eq "-") ) { delete($filts->{'severity'}); }
    if ($filts->{'resource'} && ($filts->{'resource'} eq "-") ) { delete($filts->{'resource'}); }

    if ($filts->{'mode'} && ($filts->{'mode'} eq "-" || $filts->{'mode'} eq "All") ) {
        delete($filts->{'mode'});
    }

    if ($filts->{'sdmode'} && ($filts->{'sdmode'} eq "-" || $filts->{'sdmode'} eq "All") ) {
        delete($filts->{'sdmode'});
    }
    ############################################################

	$filts = rewriteModes($filts);

	return $filts;
}

# returns ref to active filters for the specific SIR report
sub getSirFilters {

    my $args = shift;
    my $repName = undef;

    if ( $args && $args->{'name'} ) {
        $repName = $args->{'name'};
    } else {
	    $repName = "Security.Incident.Report";
	}

    my $repConf = '/etc/apparmor/reports.conf';
    my $rec = undef;

	my $filts = getXmlReport($repName);

    # Clean hash of useless refs
    for (sort keys(%$filts) ) {
        if ($filts->{$_} eq "-") {
            delete($filts->{$_});
        }
    }

	# remove non-filter info
	if ( $filts->{'name'} ) { delete( $filts->{'name'}); }
	if ( $filts->{'exportpath'} ) { delete( $filts->{'exportpath'}); }
	if ( $filts->{'exporttype'} ) { delete( $filts->{'exporttype'}); }
	if ( $filts->{'addr1'} ) { delete( $filts->{'addr1'}); }
	if ( $filts->{'addr2'} ) { delete( $filts->{'addr2'}); }
	if ( $filts->{'addr3'} ) { delete( $filts->{'addr3'}); }
	if ( $filts->{'time'} ) { delete( $filts->{'time'}); }

    if ( ! $args->{'gui'} || $args->{'gui'} ne "1" ) {
		$filts = rewriteModes($filts);
        $filts = rewriteFilters($filts);
    }

	return $filts;
}

# deprecated (pre-xml)
sub OldgetSirFilters {

    my $args = shift;
	my $repName = undef;

	if ( $args && $args->{'name'} ) { 
		$repName = $args->{'name'};
	}

    my $repConf = '/etc/apparmor/reports.conf';
    my $rec = undef;

    if (! $repName) {
        $repName = "\"Security.Incident.Report\"";
    } else {
        $repName = "\"$repName\"";
    }

    if ( open(CF, "<$repConf") ) {

        while (<CF>) {
            next if /^#/;
            chomp;
            my ($cfRptName) = (split(/:/, $_))[0];
            $cfRptName =~ s/\s+$//;         # remove trailing spaces

            next unless ($cfRptName eq "$repName");

			# Name : csv.html : prog, prof, pid, res, sev, sdmode, mode : (up to 3) email addresses : last run time
            my ($name,$info) = split(/:/, $_, 2);
            $info =~ s/\s+//g;
            $name =~ s/^\s+//;
            $name =~ s/\s+$//;
            my ($mailtype, $filters, $email, $lastRun) = split(/\s*:\s*/, $info, 4);

            $rec->{'name'} = $name;
            $rec->{'name'} =~ s/\"//g;
            ($rec->{'prog'}, $rec->{'profile'}, $rec->{'pid'}, $rec->{'resource'},
            $rec->{'severity'}, $rec->{'sdmode'}, $rec->{'mode'}) = split(/\,/, $filters, 7);

        }

        close CF;
    } else {
        logError("Couldn't open $repConf.  No filters will be used in report generation.");
        return;
    }

    # Clean hash of useless refs
    for (sort keys(%$rec) ) {
        if ($rec->{$_} eq "-") {
            delete($rec->{$_});
        }
    }

	$rec = rewriteModes($rec);

	if ( ! $args->{'gui'} || $args->{'gui'} ne "1" ) {
		$rec = rewriteFilters($rec);
	}

    return $rec;
}

# Main SIR report generator
sub getEvents {

	my ($query, $start, $end, $dbFile) = @_;
	my @events = ();
	my $prevTime = 0;
	my $prevDate = '0';

	if ( ! $query || $query !~ /^SELECT/ ) { $query = "SELECT * FROM events"; }
	if ( $dbFile && -f $dbFile ) { $eventDb = $dbFile; }

	my $hostName = `/bin/hostname` || 'unknown';
	chomp $hostName unless $hostName eq 'unknown';

	if ( ! $start) { $start = '1104566401'; }	# Give default start of 1/1/2005 
	if ( ! $end) { $end = time; }

	# make sure they don't give us a bad range
	($start, $end) = ($end, $start) if $start > $end;

	# Events Schema
	# - (id,time,counter,pid,sdmode,type,mode,resource,target,profile,prog,severity);

	# Pull stuff from db
	my $dbh = DBI->connect("dbi:SQLite:dbname=$eventDb", "", "", {RaiseError => 1, AutoCommit => 1});
	my $all = undef;
	eval {
	    $all = $dbh->selectall_arrayref("$query");
	};

	if ( $@ ) {
        Immunix::Ycp::y2error(sprintf(gettext("DBI Execution failed: %s."), $DBI::errstr));
		return;
	}

	$dbh->disconnect();

    for my $row (@$all) {
		my $rec = undef;
        ($rec->{'id'}, $rec->{'time'}, $rec->{'counter'}, $rec->{'pid'}, $rec->{'sdmode'}, $rec->{'type'},
            $rec->{'mode'}, $rec->{'resource'}, $rec->{'target'}, $rec->{'profile'}, $rec->{'prog'}, $rec->{'severity'} ) = @$row;

		# Give empty record values a default value
		if ( ! $rec->{'host'} ) { $rec->{'host'} = $hostName; }
		for (keys(%$rec)) { if ( !$rec->{$_} ) { $rec->{$_} = '-'; } } 

		# Change 'time' to date
        if ( $rec->{'time'} && $rec->{'time'} == $prevTime ) {
            $rec->{'date'} = $prevDate;
        } elsif ( $rec->{'time'} ) {
            my $newDate = getDate("$rec->{'time'}");
            $rec->{'date'} = $newDate;
            $prevDate = $newDate;
            $prevTime = $rec->{'time'};
        } else {
            $rec->{'date'} = "0000-00-00-00:00:00";
        }

        if ( $rec->{'severity'} && $rec->{'severity'} eq '-1' ) {
            $rec->{'severity'} = 'U';
        }

		delete($rec->{'time'});
		delete($rec->{'counter'});

		push(@events, $rec);
    }

    return \@events;
}

# Archived Reports Stuff -- Some of this would go away in an ideal world
################################################################################
sub getArchReport {

	my $args = shift;
	my @rec = ();
    my $eventRep = "/var/log/apparmor/reports/events.rpt";

	#if ( $args->{'type'} && $args->{'type'} eq 'archRep' ) {}
	if ( $args->{'logFile'} ) {
		$eventRep = $args->{'logFile'}; 
	}

    if ( open(REP, "<$eventRep") ) {

		my $page = 1;

		if ( $args->{'page'} ) { $page = $args->{'page'}; }

		my $id = 1;
		my $slurp = 0;
		#my $numPages = 0;

		my $prevTime = undef;
		my $prevDate = undef;

		while (<REP>)  {

			my $db = ();

			# Why not get rid of page and just do divide by $i later?
			if (/Page/) {
		#		$numPages++;
                chomp;
                if ($_ eq "Page $page") {
					$slurp = 1;
				} else {
					$slurp = 0;
				}
			} elsif ( $slurp == 1 ) {

				chomp;

				($db->{'host'}, $db->{'time'}, $db->{'prog'}, $db->{'profile'},  $db->{'pid'},  $db->{'severity'},
				$db->{'mode'}, $db->{'denyRes'}, $db->{'sdmode'} ) = split(/\,/, $_);

				# Convert epoch time to date
				if ($db->{'time'} == $prevTime) {
					$db->{'date'} = $prevDate;
				} else {
					$prevTime = $db->{'time'};
					$prevDate = getDate("$db->{'time'}");
					$db->{'date'} = $prevDate;
				}

				$id++;
				$db->{'date'} = $db->{'time'};
				delete $db->{'time'};
				push(@rec, $db);	
			}
		}


		close REP;

	} else {
        Immunix::Ycp::y2error(sprintf(gettext("Fatal Error.  getArchReport() couldn't open %s"), $eventRep));
		return("Couldn't open $eventRep");
	}

	return(\@rec);
}

sub writeEventReport {

    my ( $db, $args) = @_;      # Filters for date, && regexp
    #my $type = shift || undef;
    my $eventRep = "/var/log/apparmor/reports/events.rpt";

    # Not sure if this is needed anymore, but it messes up archived SIR reports
    # if ( $args->{'logFile'} ) { $eventRep = $args->{'logFile'}; }

    if ( open(REP, ">$eventRep") ) {

        my $i = 1;
        my $page = 1;
        my $skip = 0;

        # Title for scheduled reports
        if ( $args->{'title'} ) { print REP "$args->{'title'}"; }

        print REP "Page $page\n";
        $page++;

        for (@$db) {

            print REP "$_->{'host'},$_->{'date'},$_->{'prog'},$_->{'profile'},$_->{'pid'},$_->{'severity'},$_->{'mode'},$_->{'resource'},$_->{'sdmode'}\n";

            if ( ($i % $numEvents) == 0 && $skip == 0) {
                print REP "Page $page\n";
                $page++;
                $skip = 1;
            } else {
                $i++;
                $skip = 0;
            }

        }

        close REP;

    } else {
        return("Couldn't open $eventRep");
    }

    return 0;
}

sub prepSingleLog {

    my $args = shift;

    my $dir = '/var/log/apparmor/reports-archived';
    my $error = "0";
    my @errors = ();                        # For non-fatal errors
    my @repList = ();
	my $readFile = "";
    my $eventRep = "/var/log/apparmor/reports/all-reports.rpt";		# write summary to this file - changed 04-14-2005
    #my $eventRep = "/tmp/events.rpt";			# write summary to this file

    if ( $args->{'logFile'} ) { $readFile = $args->{'logFile'}; }
    if ( $args->{'repPath'} ) { $dir = $args->{'repPath'}; }

    my @rawDb = ();
    my $numPages = 1;
    my $numRecords = 1;
    my $skip = 0;

    # Open record compilation file
    if ( open(RREP, "<$dir/$readFile") ) {

	    if ( open(WREP, ">$eventRep") ) {
#	            print WREP "Page $numPages\n";
	            $numPages++;

			while(<RREP>) {

				next if (/Page/);
				next if /^#/;

                print WREP "$_";

                if ( ($numRecords % $numEvents) == 0 && $skip == 0) {
                    print WREP "Page $numPages\n";
                    $numPages++;
                    $skip = 1;
                } else {
                    $numRecords++;
                    $skip = 0;
				}

			}
			close WREP;
	    } else {
	        $error = "Problem in prepSingleLog() - couldn't open $eventRep.";
	        return $error;
	    }

		close RREP;

    } else {
        $error = "Problem in prepSingleLog() - couldn't open -$dir/$readFile-.";
        return $error;
    }

    return $error;
}

# Cats files in specified directory for easier parsing
sub prepArchivedLogs {

	my $args = shift;

	my $dir = '/var/log/apparmor/reports-archived';
	my $error = "0";
	my @errors = ();						# For non-fatal errors
	my @repList = ();
	my @db = ();
	my $eventRep = "/var/log/apparmor/reports/all-reports.rpt";

	my $useFilters = 0;

	if ( $args->{'logFile'} ) {
		$eventRep = $args->{'logFile'}; 
	}

	if ( $args->{'repPath'} ) {
		$dir = $args->{'repPath'};
	}

	# Check to see if we need to use filters
    if ( $args->{'mode'} && ( $args->{'mode'} =~ /All/ || $args->{'mode'} =~ /^\s*-\s*$/) ) {
        delete($args->{'mode'});
    }
    if ( $args->{'sdmode'} && ( $args->{'sdmode'} =~ /All/ || $args->{'sdmode'} =~ /^\s*-\s*$/) ) {
        delete($args->{'sdmode'});
    }
    if ( $args->{'resource'} && ( $args->{'resource'} =~ /All/ || $args->{'resource'} =~ /^\s*-\s*$/) ) {
        delete($args->{'resource'});
    }
    if ( $args->{'sevLevel'} && ( $args->{'sevLevel'} =~ /All/ || $args->{'sevLevel'} =~ /^\s*-\s*$/) ) {
        delete($args->{'sevLevel'});
    }

	if ( $args->{'prog'} || $args->{'profile'} || $args->{'pid'} || $args->{'denyRes'} || 
			$args->{'mode'} || $args->{'sdmode'} || ($args->{'startdate'} && $args->{'enddate'} ) ) { 

		$useFilters = 1;
	}
	############################################################	


	# Get list of files in archived report directory
	if ( opendir (RDIR, $dir) ) {

        my @firstPass = grep(/csv/, readdir(RDIR));
        @repList = grep(!/Applications.Audit|Executive.Security.Summary/, @firstPass);
		close RDIR;

	} else {
		$error = "Failure in prepArchivedLogs() - couldn't open $dir.";
		return($error);		# debug - exit instead?
	}

	my @rawDb = ();
    my $numPages = 1;
    my $numRecords = 1;

	# Open record compilation file
    if ( open(AREP, ">$eventRep") ) {

		for (@repList) {

			my $file = $_;

			# Cycle through each $file in $dir
			if (open (RPT, "<$dir/$file") ) {
				push(@rawDb, <RPT>);
		        close RPT;
			} else {
				$error = "Problem in prepArchivedLogs() - couldn't open $dir/$file.";
				push(@errors, $error);
			}
		}

		# sort & store cat'd files
		if (@rawDb > 0 ) {

			# Run Filters
			if ( $useFilters == 1 ) {

				my @tmpDb = parseMultiDb($args,@rawDb);
				@db = sort(@tmpDb);

			} else {
				@db = sort(@rawDb);
			}

	        my $skip = 0;
	        print AREP "Page $numPages\n";
	        $numPages++;

			for (@db) {

				next if /^Page/;
				next if /^#/;

	            print AREP "$_";

	            if ( ($numRecords % $numEvents) == 0 && $skip == 0) {
	                print AREP "Page $numPages\n";
	                $numPages++;
	                $skip = 1;
	            } else {
	                $numRecords++;
	                $skip = 0;
	            }
			}

		} else {
			$error = "DB created from $dir is empty.";
		}

		close AREP;

	} else {
		$error = "Problem in prepArchivedLogs() - couldn't open $eventRep.";
		push(@errors, $error);
	}

	return $error;
}

# Similar to parseLog(), but expects @db to be passed
sub parseMultiDb {

    my ($args,@db) = @_;
	my @newDb = ();

    my $error = undef;
    my $startDate = undef;
    my $endDate = undef;

    # deref dates for speed
    if ($args->{'startdate'} && $args->{'enddate'} ) {
        $startDate = getEpochFromNum("$args->{'startdate'}",'start');
        $endDate = getEpochFromNum("$args->{'enddate'}",'end');
    }

	$args = rewriteModes($args);

	for (@db) {

        my $rec = undef;
		my $line = $_;

        next if /true|false/;               # avoid horrible yast bug
        next if /^Page/;
        next if /^#/;
        chomp;
        next if (! $_ || $_ eq "");

        # Lazy filters -- maybe these should be with the rest below
        if ( $args->{'prog'} ) { next unless /$args->{'prog'}/; }
        if ( $args->{'profile'} ) { next unless /$args->{'profile'}/; }

        # Need (epoch) 'time' element here, do we want to store 'date' instead?
        ($rec->{'host'},$rec->{'time'},$rec->{'prog'},$rec->{'profile'},
        $rec->{'pid'},$rec->{'sevLevel'},$rec->{'mode'}, $rec->{'resource'}, $rec->{'sdmode'})
            = split(/\,/, $_);

        # Make sure we get the time/date ref. name right.  If it's $args->"time",
        # the arg will be converted to a human-friendly "date" ref in writeEventReport().
        if ($rec->{'time'} =~ /\:|\-/ ) {
            $rec->{'date'} = $rec->{'time'};
            delete $rec->{'time'};
        }

        # Check filters
        if ( $args->{'pid'} && $args->{'pid'} ne '-' ) {
            next unless ($args->{'pid'} eq $rec->{'pid'});
        }
        if ( $args->{'sevLevel'} && $args->{'sevLevel'} ne "00" && $args->{'sevLevel'} ne '-' ) {
            if ( $args->{'sevLevel'} eq "U" ) { $args->{'sevLevel'} = '-1'; }
            next unless ($args->{'sevLevel'} eq $rec->{'sevLevel'});
        }
        if ( $args->{'mode'} && $args->{'mode'} ne '-' ) {
            next unless ($args->{'mode'} eq $rec->{'mode'});
        }

        if ( $args->{'denyRes'} && $args->{'denyRes'} ne '-' ) {
            next unless ($args->{'denyRes'} eq $rec->{'denyRes'});
        }
        if ( $args->{'sdmode'} && $args->{'sdmode'} ne '-' ) {
                # Needs reversal of comparison for sdmode
                next unless ( $rec->{'sdmode'} =~ /$args->{'sdmode'}/ );
        }

        push(@newDb, $line);

    }

	return @newDb;
}

# Grab & filter events from archived reports (.csv files) 
sub parseLog {

    my $args = shift;

	my @db = ();
    my $eventRep = "/var/log/apparmor/reports/events.rpt";

	if ( $args->{'logFile'} ) {
		$eventRep = $args->{'logFile'};
	}

	#my $id = keys(%$db);
	#my $rec = undef;
	my $error = undef;
    my $startDate = undef;
    my $endDate = undef;

    # deref dates for speed
    if ($args->{'startdate'} && $args->{'enddate'} ) {
        $startDate = getEpochFromNum("$args->{'startdate'}",'start');
        $endDate = getEpochFromNum("$args->{'enddate'}",'end');
    }

	#if ( $args->{'mode'} && ( $args->{'mode'} =~ /All/ || $args->{'mode'} =~ /\s*\-\s*/) ) {}
	if ( $args->{'mode'} && ( $args->{'mode'} =~ /All/ || $args->{'mode'} =~ /^\s*-\s*$/) ) {
		delete($args->{'mode'});
	}
	if ( $args->{'sdmode'} && ( $args->{'sdmode'} =~ /All/ || $args->{'sdmode'} =~ /^\s*-\s*$/) ) {
		delete($args->{'sdmode'});
	}
	if ( $args->{'resource'} && ( $args->{'resource'} =~ /All/ || $args->{'resource'} =~ /^\s*-\s*$/) ) {
		delete($args->{'resource'});
	}
	if ( $args->{'sevLevel'} && ( $args->{'sevLevel'} =~ /All/ || $args->{'sevLevel'} =~ /^\s*-\s*$/) ) {
		delete($args->{'sevLevel'});
	}

	$args = rewriteModes($args);

	if ( open (LOG, "<$eventRep") ) {

	    # Log Parsing
	    while (<LOG>) {

			my $rec = undef;

			next if /true|false/;				# avoid horrible yast bug
			next if /Page/;
			next if /^#/;
			chomp;
			next if (! $_ || $_ eq "");

			# Lazy filters -- maybe these should be with the rest below
			if ( $args->{'prog'} ) { next unless /$args->{'prog'}/; }
			if ( $args->{'profile'} ) { next unless /$args->{'profile'}/; }

			# Need (epoch) 'time' element here, do we want to store 'date' instead?
			($rec->{'host'},$rec->{'time'},$rec->{'prog'},$rec->{'profile'},
			$rec->{'pid'},$rec->{'sevLevel'},$rec->{'mode'}, $rec->{'resource'}, $rec->{'sdmode'}) 
				= split(/\,/, $_);

			# Make sure we get the time/date ref. name right.  If it's $args->"time", 
			# the arg will be converted to a human-friendly "date" ref in writeEventReport().
            if ($rec->{'time'} =~ /\:|\-/ ) {
				$rec->{'date'} = $rec->{'time'};
				delete $rec->{'time'};
            }

			# Check filters
			if ( $args->{'pid'} && $args->{'pid'} ne '-' ) { 
				next unless ($args->{'pid'} eq $rec->{'pid'}); 
			}
			if ( $args->{'sevLevel'} && $args->{'sevLevel'} ne "00" && $args->{'sevLevel'} ne '-' ) { 
				next unless ($args->{'sevLevel'} eq $rec->{'sevLevel'}); 
			}
			if ( $args->{'mode'} && $args->{'mode'} ne '-' ) { 
				next unless ($args->{'mode'} eq $rec->{'mode'}); 
			}
			if ( $args->{'denyRes'} && $args->{'denyRes'} ne '-' ) { 
				next unless ($args->{'denyRes'} eq $rec->{'denyRes'}); 
			}
			if ( $args->{'sdmode'} && $args->{'sdmode'} ne '-' ) { 
				# Needs reversal of comparison for sdmode 
				next unless ( $rec->{'sdmode'} =~ /$args->{'sdmode'}/ );
			}

			push(@db, $rec);

		}

		close LOG;

	    # Export results to file if requested
	    if ( $args->{'exporttext'} || $args->{'exporthtml'} ) {

            my $rawLog = undef; 
	        my $expLog = undef;

			if ( $args->{'exportPath'} ) {
	            $rawLog = $args->{'exportPath'} . '/export-log';
			} else {
				$rawLog = '/var/log/apparmor/reports-exported/export-log';
			}

	        if ( $args->{'exporttext'} && $args->{'exporttext'} eq 'true') {
	            $expLog = "$rawLog.csv";
				exportLog($expLog,\@db);		# redo w/ @$db instead of %db?
	        }

	        if ( $args->{'exporthtml'} && $args->{'exporthtml'} eq 'true') {
	            $expLog = "$rawLog.html";
	            exportLog($expLog,\@db);		# redo w/ @$db instead of %db?
	        }
	    }

		# write out files to single sorted file (for state, and to speed up yast)
		#if (! $args->{'single'} ) {
		#	$error = writeEventReport(\@db, $args);
		#}

		# changed 04-13-05 - should probably do this, regardless
		$error = writeEventReport(\@db, $args);

	} else {
		$error = "Couldn't open $eventRep.";
	}

	return $error;
}

# OLD STUFF -- delete

# deprecated -- replaced by better SQL queries
sub OLDgetEssStats {

    my $args = shift;

    my $prevTime = '0';
    my $prevDate = '0';
    my $startDate = '1104566401';       # Jan 1, 2005
    my $endDate =  time;

    if ($args->{'startdate'} ) { $startDate = $args->{'startdate'}; }
    if ($args->{'enddate'} )   { $endDate   = $args->{'enddate'}; }

	my $query = "SELECT * FROM events";

    # hostIp, startDate, endDate, sevHi,  sevMean, numRejects
    my $eventDb = getEvents($query,"","$startDate","$endDate");

    my @hostIdx = ();           # Simple index to all hosts for quick host matching
    my @hostDb = ();            # Host-keyed data for doing REJECT stats

    # Outer Loop for Raw Event db
    for (@$eventDb) {

        my $ev = $_;        # current event record

        if ( $ev->{'host'} ) {

            # Create new host entry, or add to existing
            if ( grep(/$ev->{'host'}/, @hostIdx) == 1 ) {

                # Inner loop, but the number of hosts should be small
                for my $hdb (@hostDb) {

                    if ($hdb->{'host'} eq $ev->{'host'}) {

                        if ( $hdb->{'startdate'} gt $ev->{'date'} ) {
                            $hdb->{'startdate'} = $ev->{'date'};          # Find earliest start date
                        }

                        $hdb->{'numEvents'}++;            # tally all events reported for host

                        if ( $ev->{'sdmode'} ) {
                            if ( $ev->{'sdmode'} =~ /PERMIT/ ) { $hdb->{'numPermits'}++; }
                            if ( $ev->{'sdmode'} =~ /REJECT/ ) { $hdb->{'numRejects'}++; }
                            if ( $ev->{'sdmode'} =~ /AUDIT/ ) { $hdb->{'numAudits'}++; }
                        }

                        # Add stats to host entry
                        #if ( $ev->{'severity'} && $ev->{'severity'} =~ /\b\d+\b/ ) {}
                        if ( $ev->{'severity'} && $ev->{'severity'} != -1 ) {

                            $hdb->{'sevNum'}++;
                            $hdb->{'sevTotal'} = $hdb->{'sevTotal'} +  $ev->{'severity'};

                            if ($ev->{'severity'} > $hdb->{'sevHi'} ) {
                                $hdb->{'sevHi'} = $ev->{'severity'};
                            }
                        } else {
                            $hdb->{'unknown'}++;
                        }
                    }
                }

            } else {

                # New host
                my $rec = undef;
                push(@hostIdx,$ev->{'host'});   # Add host entry to index

                $rec->{'host'} = $ev->{'host'};
                $rec->{'startdate'} = $startDate;
                #$rec->{'startdate'} = $ev->{'date'};

                if ( $endDate ) {
                    $rec->{'enddate'} = $endDate;
                } else {
                    $rec->{'enddate'} = time;
                }

                # Add stats to host entry
                if ( $ev->{'sev'} && $ev->{'sev'} ne "U" ) {

                    $rec->{'sevHi'} = $ev->{'sev'};
                    $rec->{'sevTotal'} = $ev->{'sev'};
                    $rec->{'sevNum'} = 1;
                    $rec->{'unknown'} = 0;

                } else {
                    $rec->{'sevHi'} = 0;
                    $rec->{'sevTotal'} = 0;
                    $rec->{'sevNum'} = 0;
                    $rec->{'unknown'} = 1;
                }

                # Start sdmode stats
                $rec->{'numPermits'} = 0;
                $rec->{'numRejects'} = 0;
                $rec->{'numAudits'}  = 0;
                $rec->{'numEvents'}  = 1;           # tally all events reported for host

                if ( $ev->{'sdmode'} ) {
                    if ( $ev->{'sdmode'} =~ /PERMIT/ ) { $rec->{'numPermits'}++; }
                    if ( $ev->{'sdmode'} =~ /REJECT/ ) { $rec->{'numRejects'}++; }
                    if ( $ev->{'sdmode'} =~ /AUDIT/ ) { $rec->{'numAudits'}++; }
                }

                push (@hostDb,$rec);            # Add new records to host data list
            }

        } else {
            next;       # Missing host info -- big problem
        }
    }                   # END @eventDb loop

    # Process simple REJECT-related stats (for Executive Security Summaries)
    for ( @hostDb ) {

        # In the end, we want this info:
        #   - Hostname, Startdate, Enddate, # Events, # Rejects, Ave. Severity, High Severity

        if ( $_->{'sevTotal'} > 0 && $_->{'sevNum'} > 0 ) {
            $_->{'sevMean'} = Immunix::Reports::round($_->{'sevTotal'}/$_->{'sevNum'});
        } else {
            $_->{'sevMean'} = 0;
        }

        # Convert dates
        if ($_->{'startdate'} !~ /:/) {$_->{'startdate'} = Immunix::Reports::getDate($startDate); }
        if ($_->{'enddate'} !~ /:/) { $_->{'enddate'} = Immunix::Reports::getDate($_->{'enddate'}); }

        # Delete stuff that we may use in later versions (YaST is a silly, silly data handler)
        delete($_->{'sevTotal'});
        delete($_->{'sevNum'});
        delete($_->{'numPermits'});
        delete($_->{'numAudits'});
        delete($_->{'unknown'});

    }

    return(\@hostDb);
}


1;

