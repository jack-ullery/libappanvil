# $Id$
#
# ----------------------------------------------------------------------
#    Copyright (c) 2006 Novell, Inc. All Rights Reserved.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, contact Novell, Inc.
#
#    To contact Novell about this file by physical or electronic mail,
#    you may find current contact information at www.novell.com.
# ----------------------------------------------------------------------

package Immunix::SubDomain;

use strict;
use warnings;

use Carp;
use Cwd qw(cwd realpath);
use File::Basename;
use File::Temp qw/ tempfile tempdir /;
use Data::Dumper;

use Locale::gettext;
use POSIX;
use Storable qw(dclone);

use Term::ReadKey;

use Immunix::Severity;

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
    %sd
    %qualifiers
    %include
    %helpers

    $filename
    $profiledir
    $parser
    $logger
    $UI_Mode
    $running_under_genprof

    which
    getprofilefilename
    get_full_path
    fatal_error

    getprofileflags
    setprofileflags
    complain
    enforce

    autodep
    reload

    UI_GetString
    UI_GetFile
    UI_YesNo
    UI_ShortMessage
    UI_LongMessage

    UI_Important
    UI_Info
    UI_PromptUser

    getkey

    do_logprof_pass

    loadincludes
    readprofile
    readprofiles
    writeprofile
    serialize_profile

    check_for_subdomain

    setup_yast
    shutdown_yast
    GetDataFromYast
    SendDataToYast

    checkProfileSyntax
    checkIncludeSyntax
    check_qualifiers

    isSkippableFile
);

our $confdir = "/etc/apparmor";

our $repo_client;

our $running_under_genprof = 0;

our $DEBUGGING;

our $unimplemented_warning = 0;

# keep track of if we're running under yast or not - default to text mode
our $UI_Mode = "text";

our $sevdb;

our %uid2login;

# initialize Term::ReadLine if it's available
our $term;
eval {
    require Term::ReadLine;
    import Term::ReadLine;
    $term = new Term::ReadLine 'AppArmor';
};

# initialize the local poo
setlocale(LC_MESSAGES, "");
textdomain("apparmor-utils");

# where do we get our log messages from?
our $filename;

our $parser;
our $ldd;
our $logger;
our $profiledir;
our $extraprofiledir;

# we keep track of the included profile fragments with %include
my %include;

my %existing_profiles;

our $seenevents = 0;

# behaviour tweaking
our $cfg;
our $repo_cfg;

our $is_rpc_xml = 0;

# these are globs that the user specifically entered.  we'll keep track of
# them so that if one later matches, we'll suggest it again.
our @userglobs;

### THESE VARIABLES ARE USED WITHIN LOGPROF
our %t;
our %transitions;
our %sd;    # we keep track of the original profiles in %sd
our %original_sd;
our %extras;  # inactive profiles from extras

my @log;
my %pid;

my %seen;
my %profilechanges;
my %prelog;
my %log;
my %changed;
my @created;
my %skip;
our %helpers;    # we want to preserve this one between passes

my %variables;   # variables in config files

### THESE VARIABLES ARE USED WITHIN LOGPROF

sub debug ($) {
    my $message = shift;

    print DEBUG "$message\n" if $DEBUGGING;
}

my %arrows = ( A => "UP", B => "DOWN", C => "RIGHT", D => "LEFT" );

sub getkey {
    # change to raw mode
    ReadMode(4);

    my $key = ReadKey(0);

    # decode arrow key control sequences
    if ($key eq "\x1B") {
        $key = ReadKey(0);
        if ($key eq "[") {
            $key = ReadKey(0);
            if ($arrows{$key}) {
                $key = $arrows{$key};
            }
        }
    }

    # return to cooked mode
    ReadMode(0);
    return $key;
}

BEGIN {
    # set things up to log extra info if they want...
    if ($ENV{LOGPROF_DEBUG}) {
        $DEBUGGING = 1;
        open(DEBUG, ">/tmp/logprof_debug_$$.log");
        my $oldfd = select(DEBUG);
        $| = 1;
        select($oldfd);
    } else {
        $DEBUGGING = 0;
    }
}

END {
    $DEBUGGING && debug "Exiting...";

    # close the debug log if necessary
    close(DEBUG) if $DEBUGGING;
}

# returns true if the specified program contains references to LD_PRELOAD or
# LD_LIBRARY_PATH to give the PX/UX code better suggestions
sub check_for_LD_XXX ($) {
    my $file = shift;

    return undef unless -f $file;

    # limit our checking to programs/scripts under 10k to speed things up a bit
    my $size = -s $file;
    return undef unless ($size && $size < 10000);

    my $found = undef;
    if (open(F, $file)) {
        while (<F>) {
            $found = 1 if /LD_(PRELOAD|LIBRARY_PATH)/;
        }
        close(F);
    }

    return $found;
}

sub fatal_error ($) {
    my $message = shift;

    my $details = "$message\n";

    if ($DEBUGGING) {

        # we'll include the stack backtrace if we're debugging...
        $details = Carp::longmess($message);

        # write the error to the log
        print DEBUG $details;
    }

    # we'll just shoot ourselves in the head if it was one of the yast
    # interface functions that ran into an error.  it gets really ugly if
    # the yast frontend goes away and we try to notify the user of that
    # problem by trying to send the yast frontend a pretty dialog box
    my $caller = (caller(1))[3];
    exit 1 if $caller =~ /::(Send|Get)Data(To|From)Yast$/;

    # tell the user what the hell happened
    UI_Important($details);

    # make sure the frontend exits cleanly...
    shutdown_yast();

    # die a horrible flaming death
    exit 1;
}

sub setup_yast {

    # set up the yast connection if we're running under yast...
    if ($ENV{YAST_IS_RUNNING}) {

        # load the yast module if available.
        eval { require ycp; };
        unless ($@) {
            import ycp;

            $UI_Mode = "yast";

            # let the frontend know that we're starting
            SendDataToYast({
                type   => "initial_handshake",
                status => "backend_starting"
            });

            # see if the frontend is just starting up also...
            my ($ypath, $yarg) = GetDataFromYast();
            unless ($yarg
                && (ref($yarg)      eq "HASH")
                && ($yarg->{type}   eq "initial_handshake")
                && ($yarg->{status} eq "frontend_starting"))
            {

                # something's broken, die a horrible, painful death
                fatal_error "Yast frontend is out of sync from backend agent.";
            }
            $DEBUGGING && debug "Initial handshake ok";

            # the yast connection seems to be working okay
            return 1;
        }

    }

    # couldn't init yast
    return 0;
}

sub shutdown_yast {
    if ($UI_Mode eq "yast") {
        SendDataToYast({ type => "final_shutdown" });
        my ($ypath, $yarg) = GetDataFromYast();
    }
}

sub check_for_subdomain () {

    my ($support_subdomainfs, $support_securityfs);
    if (open(MOUNTS, "/proc/filesystems")) {
        while (<MOUNTS>) {
            $support_subdomainfs = 1 if m/subdomainfs/;
            $support_securityfs  = 1 if m/securityfs/;
        }
        close(MOUNTS);
    }

    my $sd_mountpoint = "";
    if (open(MOUNTS, "/proc/mounts")) {
        while (<MOUNTS>) {
            if ($support_subdomainfs) {
                $sd_mountpoint = $1 if m/^\S+\s+(\S+)\s+subdomainfs\s/;
            } elsif ($support_securityfs) {
                if (m/^\S+\s+(\S+)\s+securityfs\s/) {
                    if (-e "$1/apparmor") {
                        $sd_mountpoint = "$1/apparmor";
                    } elsif (-e "$1/subdomain") {
                        $sd_mountpoint = "$1/subdomain";
                    }
                }
            }
        }
        close(MOUNTS);
    }

    # make sure that subdomain is actually mounted there
    $sd_mountpoint = undef unless -f "$sd_mountpoint/profiles";

    return $sd_mountpoint;
}

sub which ($) {
    my $file = shift;

    foreach my $dir (split(/:/, $ENV{PATH})) {
        return "$dir/$file" if -x "$dir/$file";
    }

    return undef;
}

# we need to convert subdomain regexps to perl regexps
sub convert_regexp ($) {
    my $regexp = shift;

    # escape regexp-special characters we don't support
    $regexp =~ s/(?<!\\)(\.|\+|\$)/\\$1/g;

    # * and ** globs can't collapse to match an empty string when they're
    # the only part of the glob at a specific directory level, which
    # complicates things a little.

    # ** globs match multiple directory levels
    $regexp =~ s{(?<!\\)\*\*+}{
      my ($pre, $post) = ($`, $');
      if (($pre =~ /\/$/) && (!$post || $post =~ /^\//)) {
        'SD_INTERNAL_MULTI_REQUIRED';
      } else {
        'SD_INTERNAL_MULTI_OPTIONAL';
      }
    }gex;

    # convert * globs to match anything at the current path level
    $regexp =~ s{(?<!\\)\*}{
      my ($pre, $post) = ($`, $');
      if (($pre =~ /\/$/) && (!$post || $post =~ /^\//)) {
        'SD_INTERNAL_SINGLE_REQUIRED';
      } else {
        'SD_INTERNAL_SINGLE_OPTIONAL';
      }
    }gex;

    # convert ? globs to match a single character at current path level
    $regexp =~ s/(?<!\\)\?/[^\/]/g;

    # convert {foo,baz} to (foo|baz)
    $regexp =~ y/\{\}\,/\(\)\|/ if $regexp =~ /\{.*\,.*\}/;

    # convert internal markers to their appropriate regexp equivalents
    $regexp =~ s/SD_INTERNAL_SINGLE_OPTIONAL/[^\/]*/g;
    $regexp =~ s/SD_INTERNAL_SINGLE_REQUIRED/[^\/]+/g;
    $regexp =~ s/SD_INTERNAL_MULTI_OPTIONAL/.*/g;
    $regexp =~ s/SD_INTERNAL_MULTI_REQUIRED/[^\/].*/g;

    return $regexp;
}

sub get_full_path ($) {
    my $originalpath = shift;

    my $path = $originalpath;

    # keep track so we can break out of loops
    my $linkcount = 0;

    # if we don't have any directory foo, look in the current dir
    $path = cwd() . "/$path" if $path !~ m/\//;

    # beat symlinks into submission
    while (-l $path) {

        if ($linkcount++ > 64) {
            fatal_error "Followed too many symlinks resolving $originalpath";
        }

        # split out the directory/file components
        if ($path =~ m/^(.*)\/(.+)$/) {
            my ($dir, $file) = ($1, $2);

            # figure out where the link is pointing...
            my $link = readlink($path);
            if ($link =~ /^\//) {
                # if it's an absolute link, just replace it
                $path = $link;
            } else {
                # if it's relative, let abs_path handle it
                $path = $dir . "/$link";
            }
        }
    }

    if (-f $path) {
        my ($dir, $file) = $path =~ m/^(.*)\/(.+)$/;
        $path = realpath($dir) . "/$file";
    } else {
        $path = realpath($path);
    }

    return $path;
}

sub findexecutable ($) {
    my $bin = shift;

    my $fqdbin;
    if (-e $bin) {
        $fqdbin = get_full_path($bin);
        chomp($fqdbin);
    } else {
        if ($bin !~ /\//) {
            my $which = which($bin);
            if ($which) {
                $fqdbin = get_full_path($which);
            }
        }
    }

    unless ($fqdbin && -e $fqdbin) {
        return undef;
    }

    return $fqdbin;
}

sub complain ($) {
    my $bin    = shift;
    my $fqdbin = findexecutable($bin)
      or fatal_error(sprintf(gettext('Can\'t find %s.'), $bin));

    # skip directories
    return unless -f $fqdbin;

    UI_Info(sprintf(gettext('Setting %s to complain mode.'), $fqdbin));

    my $filename = getprofilefilename($fqdbin);
    setprofileflags($filename, "complain");
}

sub enforce ($) {
    my $bin = shift;

    my $fqdbin = findexecutable($bin)
      or fatal_error(sprintf(gettext('Can\'t find %s.'), $bin));

    # skip directories
    return unless -f $fqdbin;

    UI_Info(sprintf(gettext('Setting %s to enforce mode.'), $fqdbin));

    my $filename = getprofilefilename($fqdbin);
    setprofileflags($filename, "");
}

sub head ($) {
    my $file = shift;

    my $first = "";
    if (open(FILE, $file)) {
        $first = <FILE>;
        close(FILE);
    }

    return $first;
}

sub get_output (@) {
    my ($program, @args) = @_;

    my $ret = -1;

    my $pid;
    my @output;

    if (-x $program) {
        $pid = open(KID_TO_READ, "-|");
        unless (defined $pid) {
            fatal_error "can't fork: $!";
        }

        if ($pid) {
            while (<KID_TO_READ>) {
                chomp;
                push @output, $_;
            }
            close(KID_TO_READ);
            $ret = $?;
        } else {
            ($>, $)) = ($<, $();
            open(STDERR, ">&STDOUT")
              || fatal_error "can't dup stdout to stderr";
            exec($program, @args) || fatal_error "can't exec program: $!";

            # NOTREACHED
        }
    }

    return ($ret, @output);
}

sub get_reqs ($) {
    my $file = shift;

    my @reqs;
    my ($ret, @ldd) = get_output($ldd, $file);

    if ($ret == 0) {
        for my $line (@ldd) {
            last if $line =~ /not a dynamic executable/;
            last if $line =~ /cannot read header/;
            last if $line =~ /statically linked/;

            # avoid new kernel 2.6 poo
            next if $line =~ /linux-(gate|vdso(32|64)).so/;

            if ($line =~ /^\s*\S+ => (\/\S+)/) {
                push @reqs, $1;
            } elsif ($line =~ /^\s*(\/\S+)/) {
                push @reqs, $1;
            }
        }
    }

    return @reqs;
}

sub handle_binfmt ($$) {
    my ($profile, $fqdbin) = @_;

    my %reqs;
    my @reqs = get_reqs($fqdbin);

    while (my $library = shift @reqs) {

        $library = get_full_path($library);

        push @reqs, get_reqs($library) unless $reqs{$library}++;

        # does path match anything pulled in by includes in original profile?
        my $combinedmode = matchpathincludes($profile, $library);

        # if we found any matching entries, do the modes match?
        next if $combinedmode;

        $library = globcommon($library);
        chomp $library;
        next unless $library;

        $profile->{path}->{$library} = "mr";
    }
}

sub get_inactive_profile {
    my $fqdbin = shift;
    if ( $extras{$fqdbin} ) {
        return {$fqdbin => $extras{$fqdbin}};
    }
}


sub get_profile {
    my $fqdbin = shift;
    my $profile_data;

    my $distro     = $cfg->{repository}{distro};
    my $repository = $cfg->{repository}{url};
    my @profiles;
    my @profile_list;

    if (repo_is_enabled() && $repo_client) {
        UI_BusyStart( gettext("Connecting to repository.....") );
        my $res = $repo_client->send_request('FindProfiles',
                                             $distro,
                                             $fqdbin,
                                             "");
        UI_BusyStop();
        if (did_result_succeed($res)) {
            @profile_list = @{ $res->value };

            if (@profile_list) {
                my @uids;
                for my $p (@profile_list) {
                    my $uid      = $p->{user_id};
                    my $username = $uid2login{$uid};
                    if ($username) {
                        $p->{username} = $username;
                    } else {
                        push @uids, $uid;
                    }
                }

                if (@uids) {
                    UI_BusyStart( gettext("Connecting to repository.....") );
                    my $res =
                      $repo_client->send_request( 'LoginNamesFromUserIds',
                                                  [@uids] );
                    UI_BusyStop();
                    if (did_result_succeed($res)) {
                        my @usernames = @{ $res->value };
                        for my $uid (@uids) {
                            my $username = shift @usernames;
                            $uid2login{$uid} = $username;
                        }
                    }
                }
                for my $p (@profile_list) {
                    $p->{profile_type} = "REPOSITORY";
                    next if $p->{username};
                    my $uid      = $p->{user_id};
                    my $username = $uid2login{$uid};
                    if ($username) {
                        $p->{username} = $username;
                    } else {
                        $p->{username} = "unknown-$uid";
                    }
                }
            }
        }
    }

    my $inactive_profile = get_inactive_profile($fqdbin);
    if ( defined $inactive_profile && $inactive_profile ne "" ) {
        # set the profile to complain mode
        $inactive_profile->{$fqdbin}{$fqdbin}{flags} = "complain";
        push @profile_list,
            {
              "username"     => gettext( "Inactive local profile for ") .
                                $fqdbin,
              "profile_type" => "INACTIVE_LOCAL",
              "profile"      => serialize_profile(
                                  ${%$inactive_profile}{$fqdbin},
                                  $fqdbin
                                ),
              "profile_data" => $inactive_profile,
            };
    }

    return undef if ( @profile_list == 0 ); # No repo profiles, no inactive
                                            # profile
    my @options;
    my @tmp_list;
    my %users_list_idx =  ();
    my $preferred_present = 0;
    my $preferred_user  = $cfg->{repository}{preferred_user} || "NOVELL";

    for (my $i = 0; $i < scalar(@profile_list); $i++) {
        $users_list_idx{$profile_list[$i]->{username}} = $i;
        if ( $profile_list[$i]->{username} eq $preferred_user ) {
             $preferred_present = 1;
        } else {
            push @tmp_list, $profile_list[$i]->{username};
        }
    }

    if ( $preferred_present ) {
        push  @options, $preferred_user;
    }
    push  @options, @tmp_list;

    my $q = {};
    $q->{headers} = [];
    push @{ $q->{headers} }, gettext("Profile"), $fqdbin;

    $q->{functions} = [ "CMD_VIEW_PROFILE", "CMD_USE_PROFILE",
                        "CMD_CREATE_PROFILE", "CMD_ABORT", "CMD_FINISHED" ];

    $q->{default} = "CMD_VIEW_PROFILE";

    $q->{options}  = [@options];
    $q->{selected} = 0;

    my ($p, $ans, $arg);
    do {
        ($ans, $arg) = UI_PromptUser($q);
        $p = $profile_list[$users_list_idx{$options[$arg]}];
        for (my $i = 0; $i < scalar(@options); $i++) {
            if ($options[$i] eq $options[$arg]) {
                $q->{selected} = $i;
            }
        }

        if ($ans eq "CMD_VIEW_PROFILE") {
            if ($UI_Mode eq "yast") {
                SendDataToYast(
                    {
                        type         => "dialog-view-profile",
                        user         => $options[$arg],
                        profile      => $p->{profile},
                        profile_type => $p->{profile_type}
                    }
                );
                my ($ypath, $yarg) = GetDataFromYast();
            } else {
                my $pager = get_pager();
                open(PAGER, "| $pager");
                print PAGER gettext("Profile submitted by") .
                                    " $options[$arg]:\n\n$p->{profile}\n\n";
                close(PAGER);
            }
        } elsif ($ans eq "CMD_USE_PROFILE") {
            if ( $p->{profile_type} eq "INACTIVE_LOCAL" ) {
                $profile_data = $p->{profile_data};
                push @created, $fqdbin; # This really is ugly here
                                        # need to find a better place to mark
                                        # this as newly created
            } else {
                $profile_data =
                    use_repo_profile($fqdbin, $repository, $p);
            }
        }
    } until ($ans =~ /^CMD_(USE_PROFILE|CREATE_PROFILE)$/);

    return $profile_data;
}

sub set_repo_info {
    my ($profile_data, $repo_url, $username, $id) = @_;

    # save repository metadata
    $profile_data->{repo}{url}  = $repo_url;
    $profile_data->{repo}{user} = $username;
    $profile_data->{repo}{id}   = $id;
}

sub use_repo_profile {
    my ($fqdbin, $repo_url, $profile) = @_;

    my $profile_data = eval {
        parse_profile_data($profile->{profile}, "repository profile");
    };
    if ($@) {
        $profile_data = undef;
    }

    if ($profile_data) {
        set_repo_info($profile_data->{$fqdbin}{$fqdbin}, $repo_url,
                      $profile->{username}, $profile->{id});
    }

    return $profile_data;
}


sub create_new_profile {
    my $fqdbin = shift;

    my $profile = {
      $fqdbin => {
          flags   => "complain",
          include => { "abstractions/base" => 1    },
          path    => { $fqdbin             => "mr" },
      }
    };

    # if the executable exists on this system, pull in extra dependencies
    if (-f $fqdbin) {
        my $hashbang = head($fqdbin);
        if ($hashbang =~ /^#!\s*(\S+)/) {
            my $interpreter = get_full_path($1);
            $profile->{$fqdbin}{path}->{$interpreter} = "ix";
            if ($interpreter =~ /perl/) {
                $profile->{$fqdbin}{include}->{"abstractions/perl"} = 1;
            } elsif ($interpreter =~ m/\/bin\/(bash|sh)/) {
                $profile->{$fqdbin}{include}->{"abstractions/bash"} = 1;
            }
            handle_binfmt($profile->{$fqdbin}, $interpreter);
        } else {
          handle_binfmt($profile->{$fqdbin}, $fqdbin);
        }
    }

    # create required infrastructure hats if it's a known change_hat app
  for my $hatglob (keys %{$cfg->{required_hats}}) {
        if ($fqdbin =~ /$hatglob/) {
            for my $hat (sort split(/\s+/, $cfg->{required_hats}{$hatglob})) {
                $profile->{$hat} = { flags => "complain" };
            }
        }
    }
    push @created, $fqdbin;
    return { $fqdbin => $profile };
}

sub autodep ($) {
    my $bin = shift;
    %extras = ();

    unless ($repo_cfg || not defined $cfg->{repository}{url}) {
        $repo_cfg = read_config("repository.conf");
        if ( (not defined $repo_cfg->{repository}) ||
             ($repo_cfg->{repository}{enabled} eq "later") ) {
                ask_to_enable_repo();
        }
    }

    if (repo_is_enabled()) {
        setup_repo_client();
    }

    # findexecutable() might fail if we're running on a different system
    # than the logs were collected on.  ugly.  we'll just hope for the best.
    my $fqdbin = findexecutable($bin) || $bin;

    # try to make sure we have a full path in case findexecutable failed
    return unless $fqdbin =~ /^\//;

    # ignore directories
    return if -d $fqdbin;

    my $profile_data;
    readinactiveprofiles(); # need to read the profiles to see if an
                            # inactive local profile is present
    $profile_data = eval { get_profile($fqdbin) };

    unless ($profile_data) {
        $profile_data = create_new_profile($fqdbin);
    }

    # stick the profile into our data structure.
    attach_profile_data(\%sd, $profile_data);
    # and store a "clean" version also so we can display the changes we've
    # made during this run
    attach_profile_data(\%original_sd, $profile_data);

    if (-f "$profiledir/tunables/global") {
        my $file = getprofilefilename($fqdbin);

        unless (exists $variables{$file}) {
            $variables{$file} = { };
        }
        $variables{$file}{"#tunables/global"} = 1; # sorry
    }

    # write out the profile...
    writeprofile($fqdbin);
}

sub getprofilefilename ($) {
    my $profile = shift;

    my $filename = $profile;
    $filename =~ s/\///;                              # strip leading /
    $filename =~ s/\//./g;                            # convert /'s to .'s

    return "$profiledir/$filename";
}

sub setprofileflags ($$) {
    my $filename = shift;
    my $newflags = shift;

    if (open(PROFILE, "$filename")) {
        if (open(NEWPROFILE, ">$filename.new")) {
            while (<PROFILE>) {
                if (m/^\s*("??\/.+?"??)\s+(flags=\(.+\)\s+)*\{\s*$/) {
                    my ($binary, $flags) = ($1, $2);

                    if ($newflags) {
                        $_ = "$binary flags=($newflags) {\n";
                    } else {
                        $_ = "$binary {\n";
                    }
                } elsif (m/^(\s*\^\S+)\s+(flags=\(.+\)\s+)*\{\s*$/) {
                    my ($hat, $flags) = ($1, $2);

                    if ($newflags) {
                        $_ = "$hat flags=($newflags) {\n";
                    } else {
                        $_ = "$hat {\n";
                    }
                }
                print NEWPROFILE;
            }
            close(NEWPROFILE);
            rename("$filename.new", "$filename");
        }
        close(PROFILE);
    }
}

sub profile_exists($) {
    my $program = shift || return 0;

    # if it's already in the cache, return true
    return 1 if $existing_profiles{$program};

    # if the profile exists, mark it in the cache and return true
    my $profile = getprofilefilename($program);
    if (-e $profile) {
        $existing_profiles{$program} = 1;
        return 1;
    }

    # couldn't find a profile, so we'll return false
    return 0;
}

##########################################################################
# Here are the console/yast interface functions

sub UI_Info ($) {
    my $text = shift;

    $DEBUGGING && debug "UI_Info: $UI_Mode: $text";

    if ($UI_Mode eq "text") {
        print "$text\n";
    } else {
        ycp::y2milestone($text);
    }
}

sub UI_Important ($) {
    my $text = shift;

    $DEBUGGING && debug "UI_Important: $UI_Mode: $text";

    if ($UI_Mode eq "text") {
        print "\n$text\n";
    } else {
        SendDataToYast({ type => "dialog-error", message => $text });
        my ($path, $yarg) = GetDataFromYast();
    }
}

sub UI_YesNo ($$) {
    my $text    = shift;
    my $default = shift;

    $DEBUGGING && debug "UI_YesNo: $UI_Mode: $text $default";

    my $ans;
    if ($UI_Mode eq "text") {

        my $yes = gettext("(Y)es");
        my $no  = gettext("(N)o");

        # figure out our localized hotkeys
        my $usrmsg = "PromptUser: " . gettext("Invalid hotkey for");
        $yes =~ /\((\S)\)/ or fatal_error "$usrmsg '$yes'";
        my $yeskey = lc($1);
        $no =~ /\((\S)\)/ or fatal_error "$usrmsg '$no'";
        my $nokey = lc($1);

        print "\n$text\n";
        if ($default eq "y") {
            print "\n[$yes] / $no\n";
        } else {
            print "\n$yes / [$no]\n";
        }
        $ans = getkey() || (($default eq "y") ? $yeskey : $nokey);

        # convert back from a localized answer to english y or n
        $ans = (lc($ans) eq $yeskey) ? "y" : "n";
    } else {

        SendDataToYast({ type => "dialog-yesno", question => $text });
        my ($ypath, $yarg) = GetDataFromYast();
        $ans = $yarg->{answer} || $default;

    }

    return $ans;
}

sub UI_YesNoCancel ($$) {
    my $text    = shift;
    my $default = shift;

    $DEBUGGING && debug "UI_YesNoCancel: $UI_Mode: $text $default";

    my $ans;
    if ($UI_Mode eq "text") {

        my $yes    = gettext("(Y)es");
        my $no     = gettext("(N)o");
        my $cancel = gettext("(C)ancel");

        # figure out our localized hotkeys
        my $usrmsg = "PromptUser: " . gettext("Invalid hotkey for");
        $yes =~ /\((\S)\)/ or fatal_error "$usrmsg '$yes'";
        my $yeskey = lc($1);
        $no =~ /\((\S)\)/ or fatal_error "$usrmsg '$no'";
        my $nokey = lc($1);
        $cancel =~ /\((\S)\)/ or fatal_error "$usrmsg '$cancel'";
        my $cancelkey = lc($1);

        $ans = "XXXINVALIDXXX";
        while ($ans !~ /^(y|n|c)$/) {
            print "\n$text\n";
            if ($default eq "y") {
                print "\n[$yes] / $no / $cancel\n";
            } elsif ($default eq "n") {
                print "\n$yes / [$no] / $cancel\n";
            } else {
                print "\n$yes / $no / [$cancel]\n";
            }

            $ans = getkey();

            if ($ans) {
                # convert back from a localized answer to english y or n
                $ans = lc($ans);
                if ($ans eq $yeskey) {
                    $ans = "y";
                } elsif ($ans eq $nokey) {
                    $ans = "n";
                } elsif ($ans eq $cancelkey) {
                    $ans = "c";
                }
            } else {
                $ans = $default;
            }
        }
    } else {

        SendDataToYast({ type => "dialog-yesnocancel", question => $text });
        my ($ypath, $yarg) = GetDataFromYast();
        $ans = $yarg->{answer} || $default;

    }

    return $ans;
}

sub UI_GetString ($$) {
    my $text    = shift;
    my $default = shift;

    $DEBUGGING && debug "UI_GetString: $UI_Mode: $text $default";

    my $string;
    if ($UI_Mode eq "text") {

        if ($term) {
            $string = $term->readline($text, $default);
        } else {
            local $| = 1;
            print "$text";
            $string = <STDIN>;
            chomp($string);
        }

    } else {

        SendDataToYast({
            type    => "dialog-getstring",
            label   => $text,
            default => $default
        });
        my ($ypath, $yarg) = GetDataFromYast();
        $string = $yarg->{string};

    }
    return $string;
}

sub UI_GetFile ($) {
    my $f = shift;

    $DEBUGGING && debug "UI_GetFile: $UI_Mode";

    my $filename;
    if ($UI_Mode eq "text") {

        local $| = 1;
        print "$f->{description}\n";
        $filename = <STDIN>;
        chomp($filename);

    } else {

        $f->{type} = "dialog-getfile";

        SendDataToYast($f);
        my ($ypath, $yarg) = GetDataFromYast();
        if ($yarg->{answer} eq "okay") {
            $filename = $yarg->{filename};
        }
    }

    return $filename;
}

sub UI_BusyStart ($) {
    my $message = shift;
    $DEBUGGING && debug "UI_BusyStart: $UI_Mode";

    if ($UI_Mode eq "text") {
      UI_Info( $message );
    } else {
        SendDataToYast({
                        type    => "dialog-busy-start",
                        message => $message,
                       });
        my ($ypath, $yarg) = GetDataFromYast();
    }
}

sub UI_BusyStop  {
    $DEBUGGING && debug "UI_BusyStop: $UI_Mode";

    if ($UI_Mode ne "text") {
        SendDataToYast({ type    => "dialog-busy-stop" });
        my ($ypath, $yarg) = GetDataFromYast();
    }
}


my %CMDS = (
    CMD_ALLOW            => "(A)llow",
    CMD_DENY             => "(D)eny",
    CMD_ABORT            => "Abo(r)t",
    CMD_FINISHED         => "(F)inish",
    CMD_INHERIT          => "(I)nherit",
    CMD_PROFILE          => "(P)rofile",
    CMD_PROFILE_CLEAN    => "(P)rofile Clean Exec",
    CMD_UNCONFINED       => "(U)nconfined",
    CMD_UNCONFINED_CLEAN => "(U)nconfined Clean Exec",
    CMD_SAVE             => "(S)ave Changes",
    CMD_CONTINUE         => "(C)ontinue Profiling",
    CMD_NEW              => "(N)ew",
    CMD_GLOB             => "(G)lob",
    CMD_GLOBEXT          => "Glob w/(E)xt",
    CMD_ADDHAT           => "(A)dd Requested Hat",
    CMD_USEDEFAULT       => "(U)se Default Hat",
    CMD_SCAN             => "(S)can system log for SubDomain events",
    CMD_HELP             => "(H)elp",
    CMD_VIEW_PROFILE     => "(V)iew Profile",
    CMD_USE_PROFILE      => "(U)se Profile",
    CMD_CREATE_PROFILE   => "(C)reate New Profile",
    CMD_UPDATE_PROFILE   => "(U)pdate Profile",
    CMD_IGNORE_UPDATE    => "(I)gnore Update",
    CMD_SAVE_CHANGES     => "(S)ave Changes",
    CMD_UPLOAD_CHANGES   => "(U)pload Changes",
    CMD_VIEW_CHANGES     => "(V)iew Changes",
    CMD_ENABLE_REPO      => "(E)nable Repository",
    CMD_DISABLE_REPO     => "(D)isable Repository",
    CMD_ASK_NEVER        => "(N)ever Ask Again",
    CMD_ASK_LATER        => "Ask Me (L)ater",
    CMD_YES              => "(Y)es",
    CMD_NO               => "(N)o",
    CMD_ALL_NET          => "Allow All (N)etwork",
    CMD_NET_FAMILY       => "Allow Network Fa(m)ily",
);

sub UI_PromptUser ($) {
    my $q = shift;

    my ($cmd, $arg);
    if ($UI_Mode eq "text") {

        ($cmd, $arg) = Text_PromptUser($q);

    } else {

        $q->{type} = "wizard";

        SendDataToYast($q);
        my ($ypath, $yarg) = GetDataFromYast();

        $cmd = $yarg->{selection} || "CMD_ABORT";
        $arg = $yarg->{selected};
    }

    if ($cmd eq "CMD_ABORT") {
        confirm_and_abort();
        $cmd = "XXXINVALIDXXX";
    } elsif ($cmd eq "CMD_FINISHED") {
        confirm_and_finish();
        $cmd = "XXXINVALIDXXX";
    }

    if (wantarray) {
        return ($cmd, $arg);
    } else {
        return $cmd;
    }
}


sub UI_ShortMessage {
    my ($headline, $message) = @_;

    SendDataToYast(
        {
            type     => "short-dialog-message",
            headline => $headline,
            message  => $message
        }
    );
    my ($ypath, $yarg) = GetDataFromYast();
}

sub UI_LongMessage {
    my ($headline, $message) = @_;

    $headline = "MISSING" if not defined $headline;
    $message  = "MISSING" if not defined $message;

    SendDataToYast(
        {
            type     => "long-dialog-message",
            headline => $headline,
            message  => $message
        }
    );
    my ($ypath, $yarg) = GetDataFromYast();
}

##########################################################################
# here are the interface functions to send data back and forth between
# the yast frontend and the perl backend

# this is super ugly, but waits for the next ycp Read command and sends data
# back to the ycp front end.

sub SendDataToYast {
    my $data = shift;

    $DEBUGGING && debug "SendDataToYast: Waiting for YCP command";

    while (<STDIN>) {
        $DEBUGGING && debug "SendDataToYast: YCP: $_";
        my ($ycommand, $ypath, $yargument) = ycp::ParseCommand($_);

        if ($ycommand && $ycommand eq "Read") {

            if ($DEBUGGING) {
                my $debugmsg = Data::Dumper->Dump([$data], [qw(*data)]);
                debug "SendDataToYast: Sending--\n$debugmsg";
            }

            ycp::Return($data);
            return 1;

        } else {

            $DEBUGGING && debug "SendDataToYast: Expected 'Read' but got-- $_";

        }
    }

    # if we ever break out here, something's horribly wrong.
    fatal_error "SendDataToYast: didn't receive YCP command before connection died";
}

# this is super ugly, but waits for the next ycp Write command and grabs
# whatever the ycp front end gives us

sub GetDataFromYast {

    $DEBUGGING && debug "GetDataFromYast: Waiting for YCP command";

    while (<STDIN>) {
        $DEBUGGING && debug "GetDataFromYast: YCP: $_";
        my ($ycmd, $ypath, $yarg) = ycp::ParseCommand($_);

        if ($DEBUGGING) {
            my $debugmsg = Data::Dumper->Dump([$yarg], [qw(*data)]);
            debug "GetDataFromYast: Received--\n$debugmsg";
        }

        if ($ycmd && $ycmd eq "Write") {

            ycp::Return("true");
            return ($ypath, $yarg);

        } else {
            $DEBUGGING && debug "GetDataFromYast: Expected 'Write' but got-- $_";
        }
    }

    # if we ever break out here, something's horribly wrong.
    fatal_error "GetDataFromYast: didn't receive YCP command before connection died";
}

sub confirm_and_abort {
    my $ans = UI_YesNo(gettext("Are you sure you want to abandon this set of profile changes and exit?"), "n");
    if ($ans eq "y") {
        UI_Info(gettext("Abandoning all changes."));
        shutdown_yast();
        exit 0;
    }
}

sub confirm_and_finish {
    die "FINISHING\n";
}

##########################################################################
# this is the hideously ugly function that descends down the flow/event
# trees that we've generated by parsing the logfile

sub handlechildren {
    my $profile = shift;
    my $hat     = shift;
    my $root    = shift;

    my @entries = @$root;
    for my $entry (@entries) {
        fatal_error "$entry is not a ref" if not ref($entry);

        if (ref($entry->[0])) {
            handlechildren($profile, $hat, $entry);
        } else {

            my @entry = @$entry;
            my $type  = shift @entry;

            if ($type eq "fork") {
                my ($pid, $p, $h) = @entry;

                if (   ($p !~ /null(-complain)*-profile/)
                    && ($h !~ /null(-complain)*-profile/))
                {
                    $profile = $p;
                    $hat     = $h;
                }

                $profilechanges{$pid} = $profile;

            } elsif ($type eq "unknown_hat") {
                my ($pid, $p, $h, $sdmode, $uhat) = @entry;

                if ($p !~ /null(-complain)*-profile/) {
                    $profile = $p;
                }

                if ($sd{$profile}{$uhat}) {
                    $hat = $uhat;
                    next;
                }
                my $new_p = fetch_newer_repo_profile($profile);
                if ( UI_SelectUpdatedRepoProfile($profile, $new_p) and
                     $sd{$profile}{$uhat} ) {
                    $hat = $uhat;
                    next;
                }

                # figure out what our default hat for this application is.
                my $defaulthat;
                for my $hatglob (keys %{$cfg->{defaulthat}}) {
                    $defaulthat = $cfg->{defaulthat}{$hatglob}
                      if $profile =~ /$hatglob/;
                }
                # keep track of previous answers for this run...
                my $context = $profile;
                $context .= " -> ^$uhat";
                my $ans = $transitions{$context} || "XXXINVALIDXXX";

                while ($ans !~ /^CMD_(ADDHAT|USEDEFAULT|DENY)$/) {
                    my $q = {};
                    $q->{headers} = [];
                    push @{ $q->{headers} }, gettext("Profile"), $profile;
                    if ($defaulthat) {
                        push @{ $q->{headers} }, gettext("Default Hat"), $defaulthat;
                    }
                    push @{ $q->{headers} }, gettext("Requested Hat"), $uhat;

                    $q->{functions} = [];
                    push @{ $q->{functions} }, "CMD_ADDHAT";
                    push @{ $q->{functions} }, "CMD_USEDEFAULT" if $defaulthat;
                    push @{$q->{functions}}, "CMD_DENY", "CMD_ABORT",
                      "CMD_FINISHED";

                    $q->{default} = ($sdmode eq "PERMITTING") ? "CMD_ADDHAT" : "CMD_DENY";

                    $seenevents++;

                    $ans = UI_PromptUser($q);

                }
                $transitions{$context} = $ans;

                if ($ans eq "CMD_ADDHAT") {
                    $hat = $uhat;
                    $sd{$profile}{$hat}{flags} = $sd{$profile}{$profile}{flags};
                } elsif ($ans eq "CMD_USEDEFAULT") {
                    $hat = $defaulthat;
                } elsif ($ans eq "CMD_DENY") {
                    return;
                }

            } elsif ($type eq "capability") {
               my ($pid, $p, $h, $prog, $sdmode, $capability) = @entry;

                if (   ($p !~ /null(-complain)*-profile/)
                    && ($h !~ /null(-complain)*-profile/))
                {
                    $profile = $p;
                    $hat     = $h;
                }

                # print "$pid $profile $hat $prog $sdmode capability $capability\n";

                next unless $profile && $hat;

                $prelog{$sdmode}{$profile}{$hat}{capability}{$capability} = 1;
            } elsif (($type eq "path") || ($type eq "exec")) {
                my ($pid, $p, $h, $prog, $sdmode, $mode, $detail) = @entry;

                if (   ($p !~ /null(-complain)*-profile/)
                    && ($h !~ /null(-complain)*-profile/))
                {
                    $profile = $p;
                    $hat     = $h;
                }

                next unless $profile && $hat;
                my $domainchange = ($type eq "exec") ? "change" : "nochange";
                # escape special characters that show up in literal paths
                $detail =~ s/(\[|\]|\+|\*|\{|\})/\\$1/g;

                # we need to give the Execute dialog if they're requesting x
                # access for something that's not a directory - we'll force
                # a "ix" Path dialog for directories
                my $do_execute  = 0;
                my $exec_target = $detail;

                if ($mode =~ s/x//g) {
                    if (-d $exec_target) {
                        $mode .= "ix";
                    } else {
                        $do_execute = 1;
                    }
                }

                if ($mode eq "link") {
                    $mode = "l";
                    if ($detail =~ m/^from (.+) to (.+)$/) {
                        my ($path, $target) = ($1, $2);

                        my $frommode = "lr";
                        if (defined $prelog{$sdmode}{$profile}{$hat}{path}{$path}) {
                            $frommode .= $prelog{$sdmode}{$profile}{$hat}{path}{$path};
                        }
                        $frommode = collapsemode($frommode);
                        $prelog{$sdmode}{$profile}{$hat}{path}{$path} = $frommode;

                        my $tomode = "lr";
                        if (defined $prelog{$sdmode}{$profile}{$hat}{path}{$target}) {
                            $tomode .= $prelog{$sdmode}{$profile}{$hat}{path}{$target};
                        }
                        $tomode = collapsemode($tomode);
                        $prelog{$sdmode}{$profile}{$hat}{path}{$target} = $tomode;

                        # print "$pid $profile $hat $prog $sdmode $path:$frommode -> $target:$tomode\n";
                    } else {
                        next;
                    }
                } elsif ($mode) {
                    my $path = $detail;

                    if (defined $prelog{$sdmode}{$profile}{$hat}{path}{$path}) {
                        $mode .= $prelog{$sdmode}{$profile}{$hat}{path}{$path};
                        $mode = collapsemode($mode);
                    }
                    $prelog{$sdmode}{$profile}{$hat}{path}{$path} = $mode;

                    # print "$pid $profile $hat $prog $sdmode $mode $path\n";
                }

                if ($do_execute) {
                    next if ( profile_exec_access_check( $profile,
                                                         $hat,
                                                         "exec",
                                                         $exec_target ) );
                    my $p = fetch_newer_repo_profile($profile);
                    next if ( UI_SelectUpdatedRepoProfile($profile, $p) and
                              profile_exec_access_check( $profile,
                                                         $hat,
                                                         "exec",
                                                         $exec_target ) );
                    my $context = $profile;
                    $context .= "^$hat" if $profile ne $hat;
                    $context .= " -> $exec_target";
                    my $ans = $transitions{$context} || "";

                    my ($combinedmode, $cm, @m);

                    # does path match any regexps in original profile?
                    ($cm, @m) = rematchfrag($sd{$profile}{$hat}, $exec_target);
                    $combinedmode .= $cm if $cm;

                    # does path match anything pulled in by includes in
                    # original profile?
                    ($cm, @m) = matchpathincludes($sd{$profile}{$hat}, $exec_target);
                    $combinedmode .= $cm if $cm;

                    my $exec_mode;
                    if (contains($combinedmode, "ix")) {
                        $ans       = "CMD_INHERIT";
                        $exec_mode = "ixr";
                    } elsif (contains($combinedmode, "px")) {
                        $ans       = "CMD_PROFILE";
                        $exec_mode = "px";
                    } elsif (contains($combinedmode, "ux")) {
                        $ans       = "CMD_UNCONFINED";
                        $exec_mode = "ux";
                    } elsif (contains($combinedmode, "Px")) {
                        $ans       = "CMD_PROFILE_CLEAN";
                        $exec_mode = "Px";
                    } elsif (contains($combinedmode, "Ux")) {
                        $ans       = "CMD_UNCONFINED_CLEAN";
                        $exec_mode = "Ux";
                    } else {
                        my $options = $cfg->{qualifiers}{$exec_target} || "ipu";

                        # force "ix" as the only option when the profiled
                        # program executes itself
                        $options = "i" if $exec_target eq $profile;

                        # we always need deny...
                        $options .= "d";

                        # figure out what our default option should be...
                        my $default;
                        if ($options =~ /p/
                            && -e getprofilefilename($exec_target))
                        {
                            $default = "CMD_PROFILE";
                        } elsif ($options =~ /i/) {
                            $default = "CMD_INHERIT";
                        } else {
                            $default = "CMD_DENY";
                        }

                        # ugh, this doesn't work if someone does an ix before
                        # calling this particular child process.  at least
                        # it's only a hint instead of mandatory to get this
                        # right.
                        my $parent_uses_ld_xxx = check_for_LD_XXX($profile);

                        my $severity = $sevdb->rank($exec_target, "x");

                        # build up the prompt...
                        my $q = {};
                        $q->{headers} = [];
                        push @{ $q->{headers} }, gettext("Profile"), combine_name($profile, $hat);
                        if ($prog && $prog ne "HINT") {
                            push @{ $q->{headers} }, gettext("Program"), $prog;
                        }
                        push @{ $q->{headers} }, gettext("Execute"),  $exec_target;
                        push @{ $q->{headers} }, gettext("Severity"), $severity;

                        $q->{functions} = [];

                        my $prompt = "\n$context\n";
                        push @{ $q->{functions} }, "CMD_INHERIT"
                          if $options =~ /i/;
                        push @{ $q->{functions} }, "CMD_PROFILE"
                          if $options =~ /p/;
                        push @{ $q->{functions} }, "CMD_UNCONFINED"
                          if $options =~ /u/;
                        push @{$q->{functions}}, "CMD_DENY", "CMD_ABORT",
                          "CMD_FINISHED";
                        $q->{default} = $default;

                        $options = join("|", split(//, $options));

                        $seenevents++;

                        while ($ans !~ m/^CMD_(INHERIT|PROFILE|PROFILE_CLEAN|UNCONFINED|UNCONFINED_CLEAN|DENY)$/) {
                            $ans = UI_PromptUser($q);

                            if ($ans eq "CMD_PROFILE") {
                                my $px_default = "n";
                                my $px_mesg    = gettext("Should AppArmor sanitize the environment when\nswitching profiles?\n\nSanitizing the environment is more secure,\nbut some applications depend on the presence\nof LD_PRELOAD or LD_LIBRARY_PATH.");
                                if ($parent_uses_ld_xxx) {
                                    $px_mesg = gettext("Should AppArmor sanitize the environment when\nswitching profiles?\n\nSanitizing the environment is more secure,\nbut this application appears to use LD_PRELOAD\nor LD_LIBRARY_PATH and clearing these could\ncause functionality problems.");
                                }
                                my $ynans = UI_YesNo($px_mesg, $px_default);
                                if ($ynans eq "y") {
                                    $ans = "CMD_PROFILE_CLEAN";
                                }
                            } elsif ($ans eq "CMD_UNCONFINED") {
                                my $ynans = UI_YesNo(sprintf(gettext("Launching processes in an unconfined state is a very\ndangerous operation and can cause serious security holes.\n\nAre you absolutely certain you wish to remove all\nAppArmor protection when executing \%s?"), $exec_target), "n");
                                if ($ynans eq "y") {
                                    my $ynans = UI_YesNo(gettext("Should AppArmor sanitize the environment when\nrunning this program unconfined?\n\nNot sanitizing the environment when unconfining\na program opens up significant security holes\nand should be avoided if at all possible."), "y");
                                    if ($ynans eq "y") {
                                        $ans = "CMD_UNCONFINED_CLEAN";
                                    }
                                } else {
                                    $ans = "INVALID";
                                }
                            }
                        }
                        $transitions{$context} = $ans;

                        # if we're inheriting, things'll bitch unless we have r
                        if ($ans eq "CMD_INHERIT") {
                            $exec_mode = "ixr";
                        } elsif ($ans eq "CMD_PROFILE") {
                            $exec_mode = "px";
                        } elsif ($ans eq "CMD_UNCONFINED") {
                            $exec_mode = "ux";
                        } elsif ($ans eq "CMD_PROFILE_CLEAN") {
                            $exec_mode = "Px";
                        } elsif ($ans eq "CMD_UNCONFINED_CLEAN") {
                            $exec_mode = "Ux";
                        } else {

                            # skip all remaining events if they say to deny
                            # the exec
                            return if $domainchange eq "change";
                        }

                        unless ($ans eq "CMD_DENY") {
                            if (defined $prelog{PERMITTING}{$profile}{$hat}{path}{$exec_target}) {
                                $exec_mode .= $prelog{PERMITTING}{$profile}{$hat}{path}{$exec_target};
                                $exec_mode = collapsemode($exec_mode);
                            }
                            $prelog{PERMITTING}{$profile}{$hat}{path}{$exec_target} = $exec_mode;
                            $log{PERMITTING}{$profile}              = {};
                            $sd{$profile}{$hat}{path}{$exec_target} = $exec_mode;

                            # mark this profile as changed
                            $changed{$profile} = 1;

                            if ($ans eq "CMD_INHERIT") {
                                if ($exec_target =~ /perl/) {
                                    $sd{$profile}{$hat}{include}{"abstractions/perl"} = 1;
                                } elsif ($detail =~ m/\/bin\/(bash|sh)/) {
                                    $sd{$profile}{$hat}{include}{"abstractions/bash"} = 1;
                                }
                                my $hashbang = head($exec_target);
                                if ($hashbang =~ /^#!\s*(\S+)/) {
                                    my $interpreter = get_full_path($1);
                                    $sd{$profile}{$hat}{path}->{$interpreter} = "ix";
                                    if ($interpreter =~ /perl/) {
                                        $sd{$profile}{$hat}{include}{"abstractions/perl"} = 1;
                                    } elsif ($interpreter =~ m/\/bin\/(bash|sh)/) {
                                        $sd{$profile}{$hat}{include}{"abstractions/bash"} = 1;
                                    }
                                }
                            } elsif ($ans =~ /^CMD_PROFILE/) {

                                # if they want to use px, make sure a profile
                                # exists for the target.
                                unless (-e getprofilefilename($exec_target)) {
                                    $helpers{$exec_target} = "enforce";
                                    autodep($exec_target);
                                    reload($exec_target);
                                }
                            }
                        }
                    }

                    # print "$pid $profile $hat EXEC $exec_target $ans $exec_mode\n";

                    # update our tracking info based on what kind of change
                    # this is...
                    if ($ans eq "CMD_INHERIT") {
                        $profilechanges{$pid} = $profile;
                    } elsif ($ans =~ /^CMD_PROFILE/) {
                        if ($sdmode eq "PERMITTING") {
                            if ($domainchange eq "change") {
                                $profile              = $exec_target;
                                $hat                  = $exec_target;
                                $profilechanges{$pid} = $profile;
                            }
                        }
                        # if they want to use px, make sure a profile
                        # exists for the target.
                        unless (-e getprofilefilename($exec_target)) {
                               $helpers{$exec_target} = "enforce";
                               autodep($exec_target);
                               reload($exec_target);
                        }
                    } elsif ($ans =~ /^CMD_UNCONFINED/) {
                        $profilechanges{$pid} = "unconstrained";
                        return if $domainchange eq "change";
                    }
                }
            } elsif ( $type eq "netdomain" ) {
               my ($pid, $p, $h, $prog, $sdmode, $family, $sock_type, $protocol) =
                  @entry;

                if (   ($p !~ /null(-complain)*-profile/)
                    && ($h !~ /null(-complain)*-profile/))
                {
                    $profile = $p;
                    $hat     = $h;
                }

                next unless $profile && $hat;
                $prelog{$sdmode}
                       {$profile}
                       {$hat}
                       {netdomain}
                       {$family}
                       {$sock_type} = 1 unless ( !$family || !$sock_type );

            }
        }
    }
}

sub add_to_tree ($@) {
    my ($pid, $type, @event) = @_;
    if ( $DEBUGGING ) {
        my $eventmsg = Data::Dumper->Dump([@event], [qw(*event)]);
        $eventmsg =~ s/\n/ /g;
        debug " add_to_tree: pid [$pid] type [$type] event [ $eventmsg ]";
    }

    unless (exists $pid{$pid}) {
        my $arrayref = [];
        push @log, $arrayref;
        $pid{$pid} = $arrayref;
    }

    push @{ $pid{$pid} }, [ $type, $pid, @event ];
}

#
# variables used in the logparsing routines
#
our $LOG;
our $next_log_entry;
our $logmark;
our $seenmark;
my $RE_LOG_v2_0_syslog = qr/SubDomain/;
my $RE_LOG_v2_1_syslog = qr/kernel:\s+(\[[\d\.\s]+\]\s+)?audit\([\d\.\:]+\):\s+type=150[1-6]/;
my $RE_LOG_v2_0_audit  =
    qr/type=(APPARMOR|UNKNOWN\[1500\]) msg=audit\([\d\.\:]+\):/;
my $RE_LOG_v2_1_audit  =
    qr/type=(UNKNOWN\[150[1-6]\]|APPARMOR_(AUDIT|ALLOWED|DENIED|HINT|STATUS|ERROR))/;

sub prefetch_next_log_entry {
    # if we already have an existing cache entry, something's broken
    if ($next_log_entry) {
        print STDERR "Already had next log entry: $next_log_entry";
    }

    # read log entries until we either hit the end or run into an
    # AA event message format we recognize
    do {
        $next_log_entry = <$LOG>;
    } until (!$next_log_entry || $next_log_entry =~ m{
        $RE_LOG_v2_0_syslog |
        $RE_LOG_v2_0_audit  |
        $RE_LOG_v2_1_audit  |
        $RE_LOG_v2_1_syslog |
        $logmark
    }x);
}

sub get_next_log_entry {
    # make sure we've got a next log entry if there is one
    prefetch_next_log_entry() unless $next_log_entry;

    # save a copy of the next log entry...
    my $log_entry = $next_log_entry;

    # zero out our cache of the next log entry
    $next_log_entry = undef;

    return $log_entry;
}

sub peek_at_next_log_entry {
    # make sure we've got a next log entry if there is one
    prefetch_next_log_entry() unless $next_log_entry;

    # return a copy of the next log entry without pulling it out of the cache
    return $next_log_entry;
}

sub throw_away_next_log_entry {
    $next_log_entry = undef;
}

sub parse_log_record_v_2_0 ($@) {
    my ($record, $last) = @_;
    $DEBUGGING && debug "parse_log_record_v_2_0: $_";

    # What's this early out for?  As far as I can tell, parse_log_record_v_2_0
    # won't ever be called without something in $record
    return $last if ( ! $record );

    $_ = $record;

    if (s/(PERMITTING|REJECTING)-SYSLOGFIX/$1/) {
        s/%%/%/g;
    }

    if (m/LOGPROF-HINT unknown_hat (\S+) pid=(\d+) profile=(.+) active=(.+)/) {
        my ($uhat, $pid, $profile, $hat) = ($1, $2, $3, $4);

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        add_to_tree($pid, "unknown_hat", $profile, $hat,
                    "PERMITTING", $uhat);
    } elsif (m/LOGPROF-HINT (unknown_profile|missing_mandatory_profile) image=(.+) pid=(\d+) profile=(.+) active=(.+)/) {
        my ($image, $pid, $profile, $hat) = ($2, $3, $4, $5);

        return $& if $last =~ /PERMITTING x access to $image/;
        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        add_to_tree($pid, "exec", $profile, $hat, "HINT", "PERMITTING", "x", $image);

    } elsif (m/(PERMITTING|REJECTING) (\S+) access (.+) \((.+)\((\d+)\) profile (.+) active (.+)\)/) {
        my ($sdmode, $mode, $detail, $prog, $pid, $profile, $hat) =
           ($1, $2, $3, $4, $5, $6, $7);

        if (!validate_log_mode($mode)) {
            fatal_error(sprintf(gettext('Log contains unknown mode %s.'), $mode));
        }

        my $domainchange = "nochange";
        if ($mode =~ /x/) {

            # we need to try to check if we're doing a domain transition
            if ($sdmode eq "PERMITTING") {
                my $following = peek_at_next_log_entry();

                if ($following && ($following =~ m/changing_profile/)) {
                    $domainchange = "change";
                    throw_away_next_log_entry();
                }
            }
        } else {

            # we want to ignore duplicates for things other than executes...
            return $& if $seen{$&};
            $seen{$&} = 1;
        }

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        if (($profile ne 'null-complain-profile')
            && (!profile_exists($profile)))
        {
            return $&;
        }

        # currently no way to stick pipe mediation in a profile, ignore
        # any messages like this
        return $& if $detail =~ /to pipe:/;

        # strip out extra extended attribute info since we don't
        # currently have a way to specify it in the profile and
        # instead just need to provide the access to the base filename
        $detail =~ s/\s+extended attribute \S+//;

        # kerberos code checks to see if the krb5.conf file is world
        # writable in a stupid way so we'll ignore any w accesses to
        # krb5.conf
        return $& if (($detail eq "to /etc/krb5.conf") && contains($mode, "w"));

        # strip off the (deleted) tag that gets added if it's a
        # deleted file
        $detail =~ s/\s+\(deleted\)$//;

    #            next if (($detail =~ /to \/lib\/ld-/) && ($mode =~ /x/));

        $detail =~ s/^to\s+//;

        if ($domainchange eq "change") {
            add_to_tree($pid, "exec", $profile, $hat, $prog,
                        $sdmode, $mode, $detail);
        } else {
            add_to_tree($pid, "path", $profile, $hat, $prog,
                        $sdmode, $mode, $detail);
        }

    } elsif (m/(PERMITTING|REJECTING) (?:mk|rm)dir on (.+) \((.+)\((\d+)\) profile (.+) active (.+)\)/) {
        my ($sdmode, $path, $prog, $pid, $profile, $hat) =
           ($1, $2, $3, $4, $5, $6);

        # we want to ignore duplicates for things other than executes...
        return $& if $seen{$&}++;

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        add_to_tree($pid, "path", $profile, $hat, $prog, $sdmode,
                    "w", $path);

    } elsif (m/(PERMITTING|REJECTING) xattr (\S+) on (.+) \((.+)\((\d+)\) profile (.+) active (.+)\)/) {
        my ($sdmode, $xattr_op, $path, $prog, $pid, $profile, $hat) =
           ($1, $2, $3, $4, $5, $6, $7);

        # we want to ignore duplicates for things other than executes...
        return $& if $seen{$&}++;

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        my $xattrmode;
        if ($xattr_op eq "get" || $xattr_op eq "list") {
            $xattrmode = "r";
        } elsif ($xattr_op eq "set" || $xattr_op eq "remove") {
            $xattrmode = "w";
        }

        if ($xattrmode) {
            add_to_tree($pid, "path", $profile, $hat, $prog, $sdmode,
                        $xattrmode, $path);
        }

    } elsif (m/(PERMITTING|REJECTING) attribute \((.*?)\) change to (.+) \((.+)\((\d+)\) profile (.+) active (.+)\)/) {
        my ($sdmode, $change, $path, $prog, $pid, $profile, $hat) =
           ($1, $2, $3, $4, $5, $6, $7);

        # we want to ignore duplicates for things other than executes...
        return $& if $seen{$&};
        $seen{$&} = 1;

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        # kerberos code checks to see if the krb5.conf file is world
        # writable in a stupid way so we'll ignore any w accesses to
        # krb5.conf
        return $& if $path eq "/etc/krb5.conf";

        add_to_tree($pid, "path", $profile, $hat, $prog, $sdmode,
                    "w", $path);

    } elsif (m/(PERMITTING|REJECTING) access to capability '(\S+)' \((.+)\((\d+)\) profile (.+) active (.+)\)/) {
        my ($sdmode, $capability, $prog, $pid, $profile, $hat) =
           ($1, $2, $3, $4, $5, $6);

        return $& if $seen{$&};

        $seen{$&} = 1;
        $last = $&;

        # we want to ignore entries for profiles that don't exist - they're
        # most likely broken entries or old entries for deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        add_to_tree($pid, "capability", $profile, $hat, $prog,
                    $sdmode, $capability);

    } elsif (m/Fork parent (\d+) child (\d+) profile (.+) active (.+)/
        || m/LOGPROF-HINT fork pid=(\d+) child=(\d+) profile=(.+) active=(.+)/
        || m/LOGPROF-HINT fork pid=(\d+) child=(\d+)/)
    {
        my ($parent, $child, $profile, $hat) = ($1, $2, $3, $4);

        $profile ||= "null-complain-profile";
        $hat     ||= "null-complain-profile";

        $last = $&;

        # we want to ignore entries for profiles that don't exist
        # they're  most likely broken entries or old entries for
        # deleted profiles
        return $&
          if ( ($profile ne 'null-complain-profile')
            && (!profile_exists($profile)));

        my $arrayref = [];
        if (exists $pid{$parent}) {
            push @{ $pid{$parent} }, $arrayref;
        } else {
            push @log, $arrayref;
        }
        $pid{$child} = $arrayref;
        push @{$arrayref}, [ "fork", $child, $profile, $hat ];
    } else {
        $DEBUGGING && debug "UNHANDLED: $_";
    }
    return $last;
}

sub parse_log_record_v_2_1 ($) {
    $_ = shift;
    $DEBUGGING && debug "parse_log_record_v_2_1: $_";
    return if ( ! $_ );
    my $e = { };

    # first pull out any name="blah blah blah" strings
    s/\b(\w+)="([^"]+)"\s*/$e->{$1} = $2; "";/ge;

    # yank off any remaining name=value pairs
    s/\b(\w+)=(\S+)\)\'\s*/$e->{$1} = $2; "";/ge;
    s/\b(\w+)=(\S+)\,\s*/$e->{$1} = $2; "";/ge;
    s/\b(\w+)=(\S+)\s*/$e->{$1} = $2; "";/ge;

    s/\s$//;

    # audit_log_untrustedstring() is used for name, name2, and profile in
    # order to escape strings with special characters
    for my $key (keys %$e) {
        next unless $key =~ /^(name|name2|profile)$/;
        # needs to be an even number of hex characters
        if ($e->{$key} =~ /^([0-9a-f]{2})+$/i) {
            # convert the hex string back to a raw string
            $e->{$key} = pack("H*", $e->{$key});
        }
    }

    if ($e->{requested_mask} && !validate_log_mode($e->{requested_mask})) {
        fatal_error(sprintf(gettext('Log contains unknown mode %s.'), $e->{requested_mask}));
    }

    if ($e->{denied_mask} && !validate_log_mode($e->{denied_mask})) {
        fatal_error(sprintf(gettext('Log contains unknown mode %s.'), $e->{denied_mask}));
    }

    return $e;
}

sub add_event_to_tree ($) {
    my $e = shift;

    my $sdmode = "NONE";
    if ( $e->{type} =~ /(UNKNOWN\[1501\]|APPARMOR_AUDIT|1501)/ ) {
        $sdmode = "AUDIT";
    } elsif ( $e->{type} =~ /(UNKNOWN\[1502\]|APPARMOR_ALLOWED|1502)/ ) {
        $sdmode = "PERMITTING";
    } elsif ( $e->{type} =~ /(UNKNOWN\[1503\]|APPARMOR_DENIED|1503)/ ) {
        $sdmode = "REJECTING";
    } elsif ( $e->{type} =~ /(UNKNOWN\[1504\]|APPARMOR_HINT|1504)/ ) {
        $sdmode = "HINT";
    } elsif ( $e->{type} =~ /(UNKNOWN\[1505\]|APPARMOR_STATUS|1505)/ ) {
        $sdmode = "STATUS";
        return;
    } elsif ( $e->{type} =~ /(UNKNOWN\[1506\]|APPARMOR_ERROR|1506)/ ) {
        $sdmode = "ERROR";
        return;
    } else {
        $sdmode = "UNKNOWN_SD_MODE";
        return;
    }

    my ($profile, $hat);
    ($profile, $hat) = split /\/\//, $e->{profile};
    if ( $e->{operation} eq "change_hat" ) {
        ($profile, $hat) = split /\/\//, $e->{name};
    }
    $hat = $profile if ( !$hat );
    # TODO - refactor add_to_tree as prog is no longer supplied
    #        HINT is from previous format where prog was not
    #        consistently passed
    my $prog = "HINT";

    return if ($profile ne 'null-complain-profile' && !profile_exists($profile));

    if ($e->{operation} eq "exec") {
        if ( defined $e->{info} && $e->{info} eq "mandatory profile missing" ) {
            add_to_tree( $e->{pid},
                         "exec",
                         $profile,
                         $hat,
                         $sdmode,
                         "PERMITTING",
                         $e->{denied_mask},
                         $e->{name}
                       );
        }
    } elsif ($e->{operation} =~ m/file_/) {
        add_to_tree( $e->{pid},
                     "path",
                     $profile,
                     $hat,
                     $prog,
                     $sdmode,
                     $e->{denied_mask},
                     $e->{name},
                   );
    } elsif ($e->{operation} eq "capable") {
        add_to_tree( $e->{pid},
                     "capability",
                     $profile,
                     $hat,
                     $prog,
                     $sdmode,
                     $e->{name}
                   );
    } elsif ($e->{operation} =~  m/xattr/ ||
             $e->{operation} eq "setattr") {
        add_to_tree( $e->{pid},
                     "path",
                     $profile,
                     $hat,
                     $prog,
                     $sdmode,
                     $e->{denied_mask},
                     $e->{name}
                    );
    } elsif ($e->{operation} =~ m/inode_/) {
        my $is_domain_change = 0;

        if ($e->{operation}   eq "inode_permission" &&
            $e->{denied_mask} eq "x"                &&
            $sdmode           eq "PERMITTING") {

            my $following = peek_at_next_log_entry();
            if ($following) {
                my $entry = parse_log_record_v_2_1($following);
                if ($entry &&
                    $entry->{info} &&
                    $entry->{info} eq "set profile" ) {

                    $is_domain_change = 1;
                    throw_away_next_log_entry();
                }
            }
        }

        if ($is_domain_change) {
            add_to_tree( $e->{pid},
                          "exec",
                          $profile,
                          $hat,
                          $prog,
                          $sdmode,
                          $e->{denied_mask},
                          $e->{name}
                        );
        } else {
             add_to_tree( $e->{pid},
                          "path",
                          $profile,
                          $hat,
                          $prog,
                          $sdmode,
                          $e->{denied_mask},
                          $e->{name}
                        );
        }
    } elsif ($e->{operation} eq "sysctl") {
        add_to_tree( $e->{pid},
                     "path",
                     $profile,
                     $hat,
                     $prog,
                     $sdmode,
                     $e->{denied_mask},
                     $e->{name}
                   );
    } elsif ($e->{operation} eq "clone") {
        my ($parent, $child)  = ($e->{pid}, $e->{task});
        $profile ||= "null-complain-profile";
        $hat     ||= "null-complain-profile";
        my $arrayref = [];
        if (exists $pid{$e->{pid}}) {
            push @{ $pid{$parent} }, $arrayref;
        } else {
            push @log, $arrayref;
        }
        $pid{$child} = $arrayref;
        push @{$arrayref}, [ "fork", $child, $profile, $hat ];
    } elsif ($e->{operation} =~ m/socket_/) {
        add_to_tree( $e->{pid},
                     "netdomain",
                     $profile,
                     $hat,
                     $prog,
                     $sdmode,
                     $e->{family},
                     $e->{sock_type},
                     $e->{protocol},
                   );
    } elsif ($e->{operation} eq "change_hat") {
        add_to_tree($e->{pid}, "unknown_hat", $profile, $hat, $sdmode, $hat);
    } else {
        if ( $DEBUGGING ) {
            my $msg = Data::Dumper->Dump([$e], [qw(*event)]);
            debug "UNHANDLED: $msg";
        }
    }
}

sub read_log {
    $logmark = shift;
    $seenmark = $logmark ? 0 : 1;
    my $last;
    my $event_type;

    # okay, done loading the previous profiles, get on to the good stuff...
    open($LOG, $filename)
      or fatal_error "Can't read AppArmor logfile $filename: $!";
    while ($_ = get_next_log_entry()) {
        chomp;

        $seenmark = 1 if /$logmark/;

        next unless $seenmark;

        my $last_match = ""; # v_2_0 syslog record parsing requires
                             # the previous aa record in the mandatory profile
                             # case
        # all we care about is apparmor messages
        if (/$RE_LOG_v2_0_syslog/ || /$RE_LOG_v2_0_audit/) {
           $last_match = parse_log_record_v_2_0( $_, $last_match );
        } elsif (/$RE_LOG_v2_1_audit/ || /$RE_LOG_v2_1_syslog/) {
            my $event = parse_log_record_v_2_1($_);
            add_event_to_tree($event);
        } else {
            # not a known apparmor log event
            $DEBUGGING && debug "read_log UNHANDLED: $_";
        }
    }
    close($LOG);
    $logmark = "";
}


sub get_repo_profiles_for_user {
    my $username = shift;

    my $distro = $cfg->{repository}{distro};
    my $p_hash = {};
    UI_BusyStart( gettext("Connecting to repository.....") );
    my $res =
      $repo_client->send_request('FindProfiles', $distro, "", $username);
    UI_BusyStop();
    if (did_result_succeed($res)) {
        for my $p ( @$res ) {
            #
            # Parse and serialize the profile repo
            # to strip out any flags and check for parsability
            #
            my $p_repo = serialize_repo_profile( $p->{name}->value(),
                                                 $p->{profile}->value()
                                               );
            $p_hash->{$p->{name}->value()} = $p_repo if ($p_repo ne "");
        }
    } else { #FIXME HANDLE REPO ERROR
        return;
    }
    return $p_hash;
}

sub fetch_newer_repo_profile {
    my $profile = shift;

    my $distro = $cfg->{repository}{distro};
    my $url    = $sd{$profile}{$profile}{repo}{url};
    my $user   = $sd{$profile}{$profile}{repo}{user};
    my $id     = $sd{$profile}{$profile}{repo}{id};
    my $p;

    return undef unless ($distro && $url && $user && $id);
    if ($repo_client) {
        UI_BusyStart( gettext("Connecting to repository.....") );
        my $res =
          $repo_client->send_request('FindProfiles', $distro, $profile, $user);
        UI_BusyStop();
        if (did_result_succeed($res)) {
            my @profiles;
            my @profile_list = @{$res->value};

            if (@profile_list) {
                if ($profile_list[0]->{id} > $id) {
                    $p = $profile_list[0];
                }
            }
        }
    }
    return $p;
}

sub UI_SelectUpdatedRepoProfile ($$) {

    my ($profile, $p) = @_;
    my $distro        = $cfg->{repository}{distro};
    my $url           = $sd{$profile}{$profile}{repo}{url};
    my $user          = $sd{$profile}{$profile}{repo}{user};
    my $id            = $sd{$profile}{$profile}{repo}{id};
    my $updated       = 0;

    if ($p) {
        my $q = { };
        $q->{headers} = [
          "Profile", $profile,
          "User", $user,
          "Old Revision", $id,
          "New Revision", $p->{id},
        ];
        $q->{explanation} =
          gettext( "An updated version of this profile has been found in the profile repository.  Would you like to use it?");
        $q->{functions} = [
          "CMD_VIEW_CHANGES", "CMD_UPDATE_PROFILE", "CMD_IGNORE_UPDATE",
          "CMD_ABORT", "CMD_FINISHED"
        ];

        my $ans;
        do {
            $ans = UI_PromptUser($q);

            if ($ans eq "CMD_VIEW_CHANGES") {
                my $oldprofile = serialize_profile($sd{$profile}, $profile);
                my $newprofile = $p->{profile};
                display_changes($oldprofile, $newprofile);
            }
        } until $ans =~ /^CMD_(UPDATE_PROFILE|IGNORE_UPDATE)/;

        if ($ans eq "CMD_UPDATE_PROFILE") {
            eval {
                my $profile_data =
                  parse_profile_data($p->{profile}, "repository profile");
                if ($profile_data) {
                    attach_profile_data(\%sd, $profile_data);
                    $changed{$profile} = 1;
                }

                set_repo_info($sd{$profile}{$profile}, $url, $user, $p->{id});

                UI_Info(
                    sprintf(
                        gettext("Updated profile %s to revision %s."),
                        $profile, $p->{id}
                    )
                );
            };

            if ($@) {
                UI_Info(gettext("Error parsing repository profile."));
            } else {
                $updated = 1;
            }
        }
    }
    return $updated;
}

sub ask_the_questions {
    my $found; # do the magic foo-foo
    for my $sdmode (sort keys %log) {

        # let them know what sort of changes we're about to list...
        if ($sdmode eq "PERMITTING") {
            UI_Info(gettext("Complain-mode changes:"));
        } elsif ($sdmode eq "REJECTING") {
            UI_Info(gettext("Enforce-mode changes:"));
        } else {

            # if we're not permitting and not rejecting, something's broken.
            # most likely  the code we're using to build the hash tree of log
            # entries - this should never ever happen
            fatal_error(sprintf(gettext('Invalid mode found: %s'), $sdmode));
        }

        for my $profile (sort keys %{ $log{$sdmode} }) {

            my $p = fetch_newer_repo_profile($profile);
            UI_SelectUpdatedRepoProfile($profile, $p) if ( $p );

            $found++;

            # this sorts the list of hats, but makes sure that the containing
            # profile shows up in the list first to keep the question order
            # rational
            my @hats =
              grep { $_ ne $profile } keys %{ $log{$sdmode}{$profile} };
            unshift @hats, $profile
              if defined $log{$sdmode}{$profile}{$profile};

            for my $hat (@hats) {

                # step through all the capabilities first...
                for my $capability (sort keys %{ $log{$sdmode}{$profile}{$hat}{capability} }) {

                    # we don't care about it if we've already added it to the
                    # profile
                    next if profile_capability_access_check($profile,
                                                            $hat,
                                                            $capability);

                    my $severity = $sevdb->rank(uc("cap_$capability"));

                    my $defaultoption = 1;
                    my @options       = ();
                    my @newincludes;
                    @newincludes = matchcapincludes($profile,
                                                    $hat,
                                                    $capability);


                    my $q = {};

                    if (@newincludes) {
                        push @options,
                          map { "#include <$_>" } sort(uniq(@newincludes));
                    }

                    if ( @options ) {
                        push @options, "capability $capability";
                        $q->{options}  = [@options];
                        $q->{selected} = $defaultoption - 1;
                    }

                    $q->{headers} = [];
                    push @{ $q->{headers} }, gettext("Profile"), combine_name($profile, $hat);
                    push @{ $q->{headers} }, gettext("Capability"), $capability;
                    push @{ $q->{headers} }, gettext("Severity"),   $severity;

                    $q->{functions} = [
                      "CMD_ALLOW", "CMD_DENY", "CMD_ABORT", "CMD_FINISHED"
                    ];

                    # complain-mode events default to allow - enforce defaults
                    # to deny
                    $q->{default} = ($sdmode eq "PERMITTING") ? "CMD_ALLOW" : "CMD_DENY";

                    $seenevents++;
                    my $done = 0;
                    while ( not $done ) {
                        # what did the grand exalted master tell us to do?
                        my ($ans, $selected) = UI_PromptUser($q);

                        if ($ans eq "CMD_ALLOW") {

                            # they picked (a)llow, so...

                            my $selection = $options[$selected];
                            $done = 1;
                            if ($selection &&
                                $selection =~ m/^#include <(.+)>$/) {
                                my $deleted = 0;
                                my $inc = $1;
                                $deleted = delete_duplicates( $profile,
                                                               $hat,
                                                               $inc
                                                             );
                                $sd{$profile}{$hat}{include}{$inc} = 1;

                                $changed{$profile} = 1;
                                UI_Info(sprintf(
                                  gettext('Adding #include <%s> to profile.'),
                                          $inc));
                                UI_Info(sprintf(
                                  gettext('Deleted %s previous matching profile entries.'),
                                           $deleted)) if $deleted;
                            }
                            # stick the capability into the profile
                            $sd{$profile}{$hat}{capability}{$capability} = 1;

                            # mark this profile as changed
                            $changed{$profile} = 1;
                            $done = 1;
                            # give a little feedback to the user
                            UI_Info(sprintf(gettext('Adding capability %s to profile.'), $capability));
                        } elsif ($ans eq "CMD_DENY") {
                            UI_Info(sprintf(gettext('Denying capability %s to profile.'), $capability));
                            $done = 1;
                        } else {
                            redo;
                        }
                    }
                }

                # and then step through all of the path entries...
                for my $path (sort keys %{ $log{$sdmode}{$profile}{$hat}{path} }) {

                    my $mode = $log{$sdmode}{$profile}{$hat}{path}{$path};

                    # if we had an access(X_OK) request or some other kind of
                    # event that generates a "PERMITTING x" syslog entry,
                    # first check if it was already dealt with by a i/p/x
                    # question due to a exec().  if not, ask about adding ix
                    # permission.
                    if ($mode =~ /X/) {

                        # get rid of the access() markers.
                        $mode =~ s/X//g;

                        my $combinedmode = "";

                        my ($cm, @m);

                        # does path match any regexps in original profile?
                        ($cm, @m) = rematchfrag($sd{$profile}{$hat}, $path);
                        $combinedmode .= $cm if $cm;

                        # does path match anything pulled in by includes in
                        # original profile?
                        ($cm, @m) = matchpathincludes($sd{$profile}{$hat}, $path);
                        $combinedmode .= $cm if $cm;

                        if ($combinedmode) {
                            if (   contains($combinedmode, "ix")
                                || contains($combinedmode, "px")
                                || contains($combinedmode, "ux")
                                || contains($combinedmode, "Px")
                                || contains($combinedmode, "Ux"))
                            {
                            } else {
                                $mode .= "ix";
                            }
                        } else {
                            $mode .= "ix";
                        }
                    }

                    # if we had an mmap(PROT_EXEC) request, first check if we
                    # already have added an ix rule to the profile
                    if ($mode =~ /m/) {
                        my $combinedmode = "";
                        my ($cm, @m);

                        # does path match any regexps in original profile?
                        ($cm, @m) = rematchfrag($sd{$profile}{$hat}, $path);
                        $combinedmode .= $cm if $cm;

                        # does path match anything pulled in by includes in
                        # original profile?
                        ($cm, @m) = matchpathincludes($sd{$profile}{$hat}, $path);
                        $combinedmode .= $cm if $cm;

                        # ix implies m.  don't ask if they want to add an "m"
                        # rule when we already have a matching ix rule.
                        if ($combinedmode && contains($combinedmode, "ix")) {
                            $mode =~ s/m//g;
                        }
                    }

                    next unless $mode;

                    my $combinedmode = "";
                    my @matches;

                    my ($cm, @m);

                    # does path match any regexps in original profile?
                    ($cm, @m) = rematchfrag($sd{$profile}{$hat}, $path);
                    if ($cm) {
                        $combinedmode .= $cm;
                        push @matches, @m;
                    }

                    # does path match anything pulled in by includes in
                    # original profile?
                    ($cm, @m) = matchpathincludes($sd{$profile}{$hat}, $path);
                    if ($cm) {
                        $combinedmode .= $cm;
                        push @matches, @m;
                    }
                    unless ($combinedmode && contains($combinedmode, $mode)) {

                        my $defaultoption = 1;
                        my @options       = ();

                        # check the path against the available set of include
                        # files
                        my @newincludes;
                        my $includevalid;
                        for my $incname (keys %include) {
                            $includevalid = 0;

                            # don't suggest it if we're already including it,
                            # that's dumb
                            next if $sd{$profile}{$hat}{$incname};

                            # only match includes that can be suggested to
                            # the user
                            for my $incm (split(/\s+/,
                                                $cfg->{settings}{custom_includes})
                                         ) {
                                $includevalid = 1 if $incname =~ /$incm/;
                            }
                            $includevalid = 1 if $incname =~ /abstractions/;
                            next if ($includevalid == 0);

                            ($cm, @m) = matchpathinclude($incname, $path);
                            if ($cm && contains($cm, $mode)) {
                                unless (grep { $_ eq "/**" } @m) {
                                    push @newincludes, $incname;
                                }
                            }
                        }

                        # did any match?  add them to the option list...
                        if (@newincludes) {
                            push @options,
                              map { "#include <$_>" }
                              sort(uniq(@newincludes));
                        }

                        # include the literal path in the option list...
                        push @options, $path;

                        # match the current path against the globbing list in
                        # logprof.conf
                        my @globs = globcommon($path);
                        if (@globs) {
                            push @matches, @globs;
                        }

                        # suggest any matching globs the user manually entered
                        for my $userglob (@userglobs) {
                            push @matches, $userglob
                              if matchliteral($userglob, $path);
                        }

                        # we'll take the cheesy way and order the suggested
                        # globbing list by length, which is usually right,
                        # but not always always
                        push @options,
                          sort { length($b) <=> length($a) }
                          grep { $_ ne $path }
                          uniq(@matches);
                        $defaultoption = $#options + 1;

                        my $severity = $sevdb->rank($path, $mode);

                        my $done = 0;
                        while (not $done) {

                            my $q = {};
                            $q->{headers} = [];
                            push @{ $q->{headers} }, gettext("Profile"), combine_name($profile, $hat);
                            push @{ $q->{headers} }, gettext("Path"), $path;

                            # merge in any previous modes from this run
                            if ($combinedmode) {
                                $combinedmode = collapsemode($combinedmode);
                                push @{ $q->{headers} }, gettext("Old Mode"), $combinedmode;
                                $mode = collapsemode("$mode$combinedmode");
                                push @{ $q->{headers} }, gettext("New Mode"), $mode;
                            } else {
                                push @{ $q->{headers} }, gettext("Mode"), $mode;
                            }
                            push @{ $q->{headers} }, gettext("Severity"), $severity;

                            $q->{options}  = [@options];
                            $q->{selected} = $defaultoption - 1;

                            $q->{functions} = [
                              "CMD_ALLOW", "CMD_DENY", "CMD_GLOB", "CMD_GLOBEXT", "CMD_NEW",
                              "CMD_ABORT", "CMD_FINISHED"
                            ];

                            $q->{default} =
                              ($sdmode eq "PERMITTING")
                              ? "CMD_ALLOW"
                              : "CMD_DENY";

                            $seenevents++;
                            # if they just hit return, use the default answer
                            my ($ans, $selected) = UI_PromptUser($q);

                            if ($ans eq "CMD_ALLOW") {
                                $path = $options[$selected];
                                $done = 1;
                                if ($path =~ m/^#include <(.+)>$/) {
                                    my $inc = $1;
                                    my $deleted = 0;

                                    $deleted = delete_duplicates( $profile,
                                                                  $hat,
                                                                  $inc );

                                    # record the new entry
                                    $sd{$profile}{$hat}{include}{$inc} = 1;

                                    $changed{$profile} = 1;
                                    UI_Info(sprintf(gettext('Adding #include <%s> to profile.'), $inc));
                                    UI_Info(sprintf(gettext('Deleted %s previous matching profile entries.'), $deleted)) if $deleted;
                                } else {
                                    if ($sd{$profile}{$hat}{path}{$path}) {
                                        $mode = collapsemode($mode . $sd{$profile}{$hat}{path}{$path});
                                    }

                                    my $deleted = 0;
                                    for my $entry (keys %{ $sd{$profile}{$hat}{path} }) {

                                        next if $path eq $entry;

                                        if (matchregexp($path, $entry)) {

                                            # regexp matches, add it's mode to
                                            # the list to check against
                                            if (contains($mode,
                                                $sd{$profile}{$hat}{path}{$entry})) {
                                                delete $sd{$profile}{$hat}{path}{$entry};
                                                $deleted++;
                                            }
                                        }
                                    }

                                    # record the new entry
                                    $sd{$profile}{$hat}{path}{$path} = $mode;

                                    $changed{$profile} = 1;
                                    UI_Info(sprintf(gettext('Adding %s %s to profile.'), $path, $mode));
                                    UI_Info(sprintf(gettext('Deleted %s previous matching profile entries.'), $deleted)) if $deleted;
                                }
                            } elsif ($ans eq "CMD_DENY") {

                                # go on to the next entry without saving this
                                # one
                                $done = 1;
                            } elsif ($ans eq "CMD_NEW") {
                                my $arg = $options[$selected];
                                if ($arg !~ /^#include/) {
                                    $ans = UI_GetString(gettext("Enter new path: "), $arg);
                                    if ($ans) {
                                        unless (matchliteral($ans, $path)) {
                                            my $ynprompt = gettext("The specified path does not match this log entry:") . "\n\n";
                                            $ynprompt .= "  " . gettext("Log Entry") . ":    $path\n";
                                            $ynprompt .= "  " . gettext("Entered Path") . ": $ans\n\n";
                                            $ynprompt .= gettext("Do you really want to use this path?") . "\n";

                                            # we default to no if they just hit return...
                                            my $key = UI_YesNo($ynprompt, "n");

                                            next if $key eq "n";
                                        }

                                        # save this one for later
                                        push @userglobs, $ans;

                                        push @options, $ans;
                                        $defaultoption = $#options + 1;
                                    }
                                }
                            } elsif ($ans eq "CMD_GLOB") {

                                # do globbing if they don't have an include
                                # selected
                                my $newpath = $options[$selected];
                                chomp $newpath ;
                                unless ($newpath =~ /^#include/) {
                                    # is this entry directory specific
                                    if ( $newpath =~ m/\/$/ ) {
                                        # do we collapse to /* or /**?
                                        if ($newpath =~ m/\/\*{1,2}\/$/) {
                                            $newpath =~
                                            s/\/[^\/]+\/\*{1,2}\/$/\/\*\*\//;
                                        } else {
                                            $newpath =~ s/\/[^\/]+\/$/\/\*\//;
                                        }
                                    } else {
                                        # do we collapse to /* or /**?
                                        if ($newpath =~ m/\/\*{1,2}$/) {
                                            $newpath =~ s/\/[^\/]+\/\*{1,2}$/\/\*\*/;
                                        } else {
                                            $newpath =~ s/\/[^\/]+$/\/\*/;
                                        }
                                    }
                                    if ($newpath ne $selected) {
                                        push @options, $newpath;
                                        $defaultoption = $#options + 1;
                                    }
                                }
                            } elsif ($ans eq "CMD_GLOBEXT") {

                                # do globbing if they don't have an include
                                # selected
                                my $newpath = $options[$selected];
                                unless ($newpath =~ /^#include/) {
                                    # do we collapse to /*.ext or /**.ext?
                                    if ($newpath =~ m/\/\*{1,2}\.[^\/]+$/) {
                                        $newpath =~ s/\/[^\/]+\/\*{1,2}(\.[^\/]+)$/\/\*\*$1/;
                                    } else {
                                        $newpath =~ s/\/[^\/]+(\.[^\/]+)$/\/\*$1/;
                                    }
                                    if ($newpath ne $selected) {
                                        push @options, $newpath;
                                        $defaultoption = $#options + 1;
                                    }
                                }
                            } elsif ($ans =~ /\d/) {
                                $defaultoption = $ans;
                            }
                        }
                    }
                }

                # and then step through all of the netdomain entries...
                for my $family (sort keys %{$log{$sdmode}
                                                {$profile}
                                                {$hat}
                                                {netdomain}}) {

                    # TODO - severity handling for net toggles
                    #my $severity = $sevdb->rank();
                    for my $sock_type (sort keys %{$log{$sdmode}
                                                       {$profile}
                                                       {$hat}
                                                       {netdomain}
                                                       {$family}}) {

                        # we don't care about it if we've already added it to the
                        # profile
                        next if ( profile_network_access_check(
                                                               $profile,
                                                               $hat,
                                                               $family,
                                                               $sock_type
                                                              )
                                );
                        my $defaultoption = 1;
                        my @options       = ();
                        my @newincludes;
                        @newincludes = matchnetincludes($profile,
                                                        $hat,
                                                        $family,
                                                        $sock_type);

                        my $q = {};

                        if (@newincludes) {
                            push @options,
                              map { "#include <$_>" } sort(uniq(@newincludes));
                        }

                        if ( @options ) {
                            push @options, "network $family $sock_type";
                            $q->{options}  = [@options];
                            $q->{selected} = $defaultoption - 1;
                        }

                        $q->{headers} = [];
                        push @{ $q->{headers} },
                             gettext("Profile"),
                             combine_name($profile, $hat);
                        push @{ $q->{headers} },
                             gettext("Network Family"),
                             $family;
                        push @{ $q->{headers} },
                             gettext("Socket Type"),
                             $sock_type;

                        $q->{functions} = [
                                            "CMD_ALLOW",
                                            "CMD_DENY",
                                            "CMD_ABORT",
                                            "CMD_FINISHED"
                                          ];

                        # complain-mode events default to allow - enforce defaults
                        # to deny
                        $q->{default} = ($sdmode eq "PERMITTING") ? "CMD_ALLOW" :
                                                                    "CMD_DENY";

                        $seenevents++;

                        # what did the grand exalted master tell us to do?
                        my $done = 0;
                        while ( not $done ) {
                            my ($ans, $selected) = UI_PromptUser($q);

                            if ($ans eq "CMD_ALLOW") {
                                my $selection = $options[$selected];
                                $done = 1;
                                if ($selection &&
                                    $selection =~ m/^#include <(.+)>$/) {
                                    my $inc = $1;
                                    my $deleted = 0;
                                    $deleted = delete_duplicates( $profile,
                                                                   $hat,
                                                                   $inc
                                                                 );
                                    # record the new entry
                                    $sd{$profile}{$hat}{include}{$inc} = 1;

                                    $changed{$profile} = 1;
                                    UI_Info(
                                      sprintf(
                                        gettext('Adding #include <%s> to profile.'),
                                                $inc));
                                    UI_Info(
                                      sprintf(
                                        gettext('Deleted %s previous matching profile entries.'),
                                                 $deleted)) if $deleted;
                                } else {

                                    # stick the whole rule into the profile
                                    $sd{$profile}
                                       {$hat}
                                       {netdomain}
                                       {$family}
                                       {$sock_type} = 1;

                                    # mark this profile as changed
                                    $changed{$profile} = 1;

                                    # give a little feedback to the user
                                    UI_Info(sprintf(
                                           gettext('Adding network access %s %s to profile.'),
                                                    $family,
                                                    $sock_type
                                                   )
                                           );
                                }
                            } elsif ($ans eq "CMD_DENY") {
                                UI_Info(sprintf(
                                        gettext('Denying network access %s %s to profile.'),
                                                $family,
                                                $sock_type
                                               )
                                       );
                            } else {
                                redo;
                            }
                        }
                    }
                }
            }
        }
    }
}

sub delete_duplicates ($$$) {
    my ( $profile, $hat, $incname ) = @_;
    my $deleted = 0;

    ## network rules
    my $netrules = $sd{$profile}{$hat}{netdomain};
    my $incnetrules = $include{$incname}{netdomain};
    if ( $incnetrules && $netrules ) {
        my $incnetglob = defined $incnetrules->{all};

        # See which if any profile rules are matched by the include and can be
        # deleted
        for my $fam ( keys %$netrules ) {
            if ( $incnetglob || (ref($incnetrules->{$fam}) ne "HASH" &&
                                 $incnetrules->{$fam} == 1)) { # include allows
                                                               # all net or
                                                               # all fam
                if ( ref($netrules->{$fam}) eq "HASH" ) {
                    $deleted += ( keys %{$netrules->{$fam}} );
                } else {
                    $deleted++;
                }
                delete $netrules->{$fam};
            } elsif ( ref($netrules->{$fam}) ne "HASH" &&
                      $netrules->{$fam} == 1 ){
                next; # profile has all family
            } else {
                for my $socket_type ( keys %{$netrules->{$fam}} )  {
                    if ( defined $incnetrules->{$fam}{$socket_type} ) {
                        delete $netrules->{$fam}{$socket_type};
                        $deleted++;
                    }
                }
            }
        }
    }

    ## capabilities
    my $profilecaps = $sd{$profile}{$hat}{capability};
    my $inccaps = $include{$incname}{capability};
    if ( $profilecaps && $inccaps ) {
        for my $capname ( keys %$profilecaps ) {
            if ( defined $inccaps->{$capname} && $inccaps->{$capname} == 1 ) {
               delete $profilecaps->{$capname};
               $deleted++;
            }
        }
    }

    ## path rules
    for my $entry (keys %{ $sd{$profile}{$hat}{path} }) {
        next if $entry eq "#include <$incname>";
        my $cm = matchpathinclude($incname, $entry);
        if ($cm
            && contains($cm, $sd{$profile}{$hat}{path}{$entry}))
        {
            delete $sd{$profile}{$hat}{path}{$entry};
            $deleted++;
        }
    }
    return $deleted;
}

sub matchnetinclude ($$$) {
    my ($incname, $family, $type) = @_;

    my @matches;

    # scan the include fragments for this profile looking for matches
    my @includelist = ($incname);
    my @checked;
    while (my $name = shift @includelist) {
        push @checked, $name;
        return 1
          if netrules_access_check($include{$name}{netdomain}, $family, $type);
        # if this fragment includes others, check them too
        if (keys %{ $include{$name}{include} } &&
            (grep($name, @checked) == 0) ) {
            push @includelist, keys %{ $include{$name}{include} };
        }
    }
    return 0;
}

sub matchcapincludes ($$$) {
        my ($profile, $hat, $cap) = @_;

        # check the path against the available set of include
        # files
        my @newincludes;
        my $includevalid;
        for my $incname (keys %include) {
            $includevalid = 0;

            # don't suggest it if we're already including it,
            # that's dumb
            next if $sd{$profile}{$hat}{include}{$incname};

            # only match includes that can be suggested to
            # the user
            for my $incm (split(/\s+/,
                                $cfg->{settings}{custom_includes})
                         ) {
                $includevalid = 1 if $incname =~ /$incm/;
            }
            $includevalid = 1 if $incname =~ /abstractions/;
            next if ($includevalid == 0);

            push @newincludes, $incname
              if ( defined $include{$incname}{capability}{$cap} &&
                   $include{$incname}{capability}{$cap} == 1 );
        }
        return @newincludes;
}

sub matchnetincludes ($$$$) {
        my ($profile, $hat, $family, $type) = @_;

        # check the path against the available set of include
        # files
        my @newincludes;
        my $includevalid;
        for my $incname (keys %include) {
            $includevalid = 0;

            # don't suggest it if we're already including it,
            # that's dumb
            next if $sd{$profile}{$hat}{include}{$incname};

            # only match includes that can be suggested to
            # the user
            for my $incm (split(/\s+/,
                                $cfg->{settings}{custom_includes})
                         ) {
                $includevalid = 1 if $incname =~ /$incm/;
            }
            $includevalid = 1 if $incname =~ /abstractions/;
            next if ($includevalid == 0);

            push @newincludes, $incname
              if matchnetinclude($incname, $family, $type);
        }
        return @newincludes;
}

sub repo_is_enabled {

    my $enabled;
    if ($is_rpc_xml == 1 &&
	$cfg->{repository}{url} &&
        $repo_cfg &&
        $repo_cfg->{repository}{enabled} &&
        $repo_cfg->{repository}{enabled} eq "yes") {
        $enabled = 1;
    }
    return $enabled;

}

sub ask_to_enable_repo {

    my $q = { };
    return if ( not defined $cfg->{repository}{url} );
    return if ($is_rpc_xml == 0);
    $q->{headers} = [
      "Repository", $cfg->{repository}{url},
    ];
    $q->{explanation} = gettext( "Would you like to enable access to the
profile repository?" ); $q->{functions} = [ "CMD_ENABLE_REPO",
"CMD_DISABLE_REPO", "CMD_ASK_LATER", ];

    my $cmd;
    do {
        $cmd = UI_PromptUser($q);
    } until $cmd =~ /^CMD_(ENABLE_REPO|DISABLE_REPO|ASK_LATER)/;

    if ($cmd eq "CMD_ENABLE_REPO") {
        $repo_cfg->{repository}{enabled} = "yes";
    } elsif ($cmd eq "CMD_DISABLE_REPO") {
        $repo_cfg->{repository}{enabled} = "no";
    } elsif ($cmd eq "CMD_ASK_LATER") {
        $repo_cfg->{repository}{enabled} = "later";
    }

    write_config("repository.conf", $repo_cfg);
}

sub ask_to_upload_profiles {

    my $q = { };
    $q->{headers} = [
      "Repository", $cfg->{repository}{url},
    ];
    $q->{explanation} =
      gettext( "Would you like to upload newly created and changed profiles to
      the profile repository?" );
    $q->{functions} = [
      "CMD_YES", "CMD_NO", "CMD_ASK_LATER",
    ];

    my $cmd;
    do {
        $cmd = UI_PromptUser($q);
    } until $cmd =~ /^CMD_(YES|NO|ASK_LATER)/;

    if ($cmd eq "CMD_NO") {
        $repo_cfg->{repository}{upload} = "no";
    } elsif ($cmd eq "CMD_YES") {
        $repo_cfg->{repository}{upload} = "yes";
    } elsif ($cmd eq "CMD_ASK_LATER") {
        $repo_cfg->{repository}{upload} = "later";
    }

    write_config("repository.conf", $repo_cfg);
}

sub get_repo_user_pass {
    my ($user, $pass);

    if ($repo_cfg) {
        $user = $repo_cfg->{repository}{user};
        $pass = $repo_cfg->{repository}{pass};
    }

    unless ($user && $pass) {
        ($user, $pass) = ask_signup_info();
    }

    return ($user, $pass);
}

sub setup_repo_client {
    unless ($repo_client) {
        $repo_client = new RPC::XML::Client $cfg->{repository}{url};
    }
}

sub did_result_succeed {
    my $result = shift;

    my $ref = ref $result;
    return ($ref && $ref ne "RPC::XML::fault") ? 1 : 0;
}

sub get_result_error {
    my $result = shift;

    if (ref $result) {
        if (ref $result eq "RPC::XML::fault") {
            $result = $result->string;
        } else {
            $result = $$result;
        }
    }

    return $result;
}

sub ask_signup_info {

    my ($res, $save_config, $newuser, $user, $pass, $email, $signup_okay);

    if ($repo_client) {
        do {
            if ($UI_Mode eq "yast") {
                SendDataToYast(
                    {
                        type     => "dialog-repo-sign-in",
                        repo_url => $cfg->{repository}{url}
                    }
                );
                my ($ypath, $yarg) = GetDataFromYast();
                $email       = $yarg->{email};
                $user        = $yarg->{user};
                $pass        = $yarg->{pass};
                $newuser     = $yarg->{newuser};
                $save_config = $yarg->{save_config};
                if ($yarg->{cancelled} && $yarg->{cancelled} eq "y") {
                    return;
                }
                $DEBUGGING && debug("AppArmor Repository: \n\t " .
                                    ($newuser eq "1") ?
                                    "New User\n\temail: [" . $email . "]" :
                                    "Signin" . "\n\t user[" . $user . "]" .
                                    "password [" . $pass . "]\n");
            } else {
                $newuser = UI_YesNo(gettext("Create New User?"), "n");
                $user    = UI_GetString(gettext("Username: "), $user);
                $pass    = UI_GetString(gettext("Password: "), $pass);
                $email   = UI_GetString(gettext("Email Addr: "), $email)
                             if ($newuser eq "y");
                $save_config = UI_YesNo(gettext("Save Configuration? "), "y");
            }

            if ($newuser eq "y") {
                $res = $repo_client->send_request('Signup', $user, $pass, $email);
                if (did_result_succeed($res)) {
                    $signup_okay = 1;
                } else {
                    my $error  = get_result_error($res);
                    my $errmsg = gettext("The Profile Repository server returned the following error:") . "\n" .  $error .  "\n" .  gettext("Please re-enter registration information or contact the administrator");
                    if ($UI_Mode eq "yast") {
                        UI_ShortMessage(gettext("Login Error"), $errmsg);
                    } else {
                        print STDERR $errmsg;
                    }
                }
            } else {
                $res = $repo_client->send_request('LoginConfirm', $user, $pass);
                if (did_result_succeed($res)) {
                    $signup_okay = 1;
                } else {
                    my $error  = get_result_error($res);
                    my $errmsg = gettext("Login failure. Please check username and password and try again") . "\n" . $error;
                    if ($UI_Mode eq "yast") {
                        UI_ShortMessage(gettext("Login Error"), $errmsg);
                    } else {
                        UI_Important( $errmsg );
                    }
                }
            }
        } until $signup_okay;
    }

    $repo_cfg->{repository}{user} = $user;
    $repo_cfg->{repository}{pass} = $pass;
    $repo_cfg->{repository}{email} = $email;

    write_config("repository.conf", $repo_cfg) if ( $save_config eq "y" );

    return ($user, $pass);
}

sub do_logprof_pass {
    my $logmark = shift || "";

    # zero out the state variables for this pass...
    %t              = ( );
    %transitions    = ( );
    %seen           = ( );
    %sd             = ( );
    %profilechanges = ( );
    %prelog         = ( );
    @log            = ( );
    %log            = ( );
    %changed        = ( );
    %skip           = ( );
    %variables      = ( );

    UI_Info(sprintf(gettext('Reading log entries from %s.'), $filename));
    UI_Info(sprintf(gettext('Updating AppArmor profiles in %s.'), $profiledir));

    readprofiles();

    unless ($sevdb) {
        $sevdb = new Immunix::Severity("$confdir/severity.db", gettext("unknown"));
    }

    # we need to be able to break all the way out of deep into subroutine calls
    # if they select "Finish" so we can take them back out to the genprof prompt
    eval {
        unless ($repo_cfg || not defined $cfg->{repository}{url}) {
            $repo_cfg = read_config("repository.conf");
            unless ($repo_cfg && $repo_cfg->{repository}{enabled} eq "yes" ||
                    $repo_cfg && $repo_cfg->{repository}{enabled} eq "no") {
                ask_to_enable_repo();
            }
        }

        if (repo_is_enabled()) {
            setup_repo_client();
        }

        read_log($logmark);

        for my $root (@log) {
            handlechildren(undef, undef, $root);
        }

        for my $pid (sort { $a <=> $b } keys %profilechanges) {
            setprocess($pid, $profilechanges{$pid});
        }

        collapselog();

        ask_the_questions();

        if ($UI_Mode eq "yast") {
            if (not $running_under_genprof) {
                if ($seenevents) {
                    my $w = { type => "wizard" };
                    $w->{explanation} = gettext("The profile analyzer has completed processing the log files.\n\nAll updated profiles will be reloaded");
                    $w->{functions} = [ "CMD_ABORT", "CMD_FINISHED" ];
                    SendDataToYast($w);
                    my $foo = GetDataFromYast();
                } else {
                    my $w = { type => "wizard" };
                    $w->{explanation} = gettext("No unhandled AppArmor events were found in the system log.");
                    $w->{functions} = [ "CMD_ABORT", "CMD_FINISHED" ];
                    SendDataToYast($w);
                    my $foo = GetDataFromYast();
                }
            }
        }
    };

    my $finishing = 0;
    if ($@) {
        if ($@ =~ /FINISHING/) {
            $finishing = 1;
        } else {
            die $@;
        }
    }

    save_profiles();

    if (repo_is_enabled()) {
        if ( (not defined $repo_cfg->{repository}{upload}) ||
             ($repo_cfg->{repository}{upload} eq "later") ) {
             ask_to_upload_profiles();
        }
        if ($repo_cfg->{repository}{upload} eq "yes") {
            sync_profiles_with_repo();
        }
        @created = ();
    }

    # if they hit "Finish" we need to tell the caller that so we can exit
    # all the way instead of just going back to the genprof prompt
    return $finishing ? "FINISHED" : "NORMAL";
}

sub save_profiles {
    # make sure the profile changes we've made are saved to disk...
    my @changed = sort keys %changed;
    #
    # first make sure that profiles in %changed are active (or actual profiles
    # in %sd) - this is to handle the sloppiness of setting profiles as changed
    # when they are parsed in the case of legacy hat code that we want to write
    # out in an updated format
    foreach  my $profile_name ( keys %changed ) {
        if ( ! is_active_profile( $profile_name ) ) {
            delete $changed{ $profile_name };
        }
    }
    @changed = sort keys %changed;

    if (@changed) {
        if ($UI_Mode eq "yast") {
            my (@selected_profiles, $title, $explanation, %profile_changes);
            foreach my $prof (@changed) {
                my $oldprofile = serialize_profile($original_sd{$prof}, $prof);
                my $newprofile = serialize_profile($sd{$prof}, $prof);

                $profile_changes{$prof} = get_profile_diff($oldprofile,
                                                           $newprofile);
            }
            $explanation = gettext("Select which profile changes you would like to save to the\nlocal profile set");
            $title       = gettext("Local profile changes");
            SendDataToYast(
                {
                    type           => "dialog-select-profiles",
                    title          => $title,
                    explanation    => $explanation,
                    default_select => "true",
                    get_changelog  => "false",
                    profiles       => \%profile_changes
                }
            );
            my ($ypath, $yarg) = GetDataFromYast();
            if ($yarg->{STATUS} eq "cancel") {
                return;
            } else {
                my $selected_profiles_ref = $yarg->{PROFILES};
                for my $profile (@$selected_profiles_ref) {
                    writeprofile($profile);
                    reload($profile);
                }
            }
        } else {
            my $q = {};
            $q->{title}   = "Changed Local Profiles";
            $q->{headers} = [];

            $q->{explanation} =
              gettext( "The following local profiles were changed.  Would you like to save them?");

            $q->{functions} = [ "CMD_SAVE_CHANGES",
                                "CMD_VIEW_CHANGES",
                                "CMD_ABORT", ];

            $q->{default} = "CMD_VIEW_CHANGES";

            $q->{options}  = [@changed];
            $q->{selected} = 0;

            my ($p, $ans, $arg);
            do {
                ($ans, $arg) = UI_PromptUser($q);

                if ($ans eq "CMD_VIEW_CHANGES") {
                    my $which      = $changed[$arg];
                    my $oldprofile =
                      serialize_profile($original_sd{$which}, $which);
                    my $newprofile = serialize_profile($sd{$which}, $which);
                    display_changes($oldprofile, $newprofile);
                }

            } until $ans =~ /^CMD_SAVE_CHANGES/;

            for my $profile (sort keys %changed) {
                writeprofile($profile);
                reload($profile);
            }
        }
    }
}

sub is_repo_profile {
    my $profile_data = shift;

    return $profile_data->{repo}{url}  &&
           $profile_data->{repo}{user} &&
           $profile_data->{repo}{id};
}

sub get_repo_profile {

    my $id = shift;
    my $repo_profile;
    my $res = $repo_client->send_request('Show', $id);
    if (did_result_succeed($res)) {
        my $res_value = $res->value;
        $repo_profile = $res_value->{profile};
        $repo_profile = serialize_repo_profile( $res_value->{name},
                                                 $res_value->{profile} );
    } else {
        UI_Info( gettext("Error retrieving profile from repository: ") .
                 get_result_error($res)
               );
    }
    return $repo_profile;
}

#
# Parse a repository profile (already in string format)
# stripping any flags and meta data and serialize the result
#
sub serialize_repo_profile ($$)  {
    my($name, $repo_profile_data) = @_;
    my $serialize_opts = { };
    my $p_repo = "";
    $serialize_opts->{NO_FLAGS} = 1;

   return "" if ( not defined $repo_profile_data);

    # parse_repo_profile
    my $profile_data = eval {
        parse_profile_data($repo_profile_data, "repository profile");
    };
    if ($@) {
       $profile_data = undef;
    }
    if ( $profile_data ) {
       $p_repo = serialize_profile($profile_data->{$name}, $name, $serialize_opts);
    }
    return $p_repo;
}

sub sync_profiles_with_repo {

    return if (not $repo_client);
    my ($user, $pass) = get_repo_user_pass();
    return unless ( $user && $pass );

    my @repo_profiles;
    my @changed_profiles;
    my @new_profiles;
    my $users_repo_profiles = get_repo_profiles_for_user( $user );
    my $serialize_opts = { };
    $serialize_opts->{NO_FLAGS} = 1;

    #
    # Find changes made to non-repo profiles
    #
    for my $profile (sort keys %sd) {
        if (is_repo_profile($sd{$profile}{$profile})) {
            push @repo_profiles, $profile;
        }
        if ( grep(/^$profile$/, @created) )  {
            my $p_local = serialize_profile($sd{$profile},
                                            $profile,
                                            $serialize_opts);
            if ( not defined $users_repo_profiles->{$profile} ) {
                push @new_profiles,  [ $profile, $p_local, "" ];
            } else {
                my $p_repo = $users_repo_profiles->{$profile};
                if ( $p_local ne $p_repo ) {
                    push @changed_profiles, [ $profile, $p_local, $p_repo ];
                }
            }
        }
    }

    #
    # Find changes made to local profiles with repo metadata
    #
    if (@repo_profiles) {
        for my $profile (@repo_profiles) {
            my $p_local = serialize_profile($sd{$profile},
                                            $profile,
                                            $serialize_opts);
            if ( not exists $users_repo_profiles->{$profile} ) {
                push @new_profiles,  [ $profile, $p_local, "" ];
            } else {
                my $p_repo = "";
                if ( $sd{$profile}{$profile}{repo}{user} eq $user ) {
                   $p_repo = $users_repo_profiles->{$profile};
                }  else {
                    $p_repo =
                        get_repo_profile($sd{$profile}{$profile}{repo}{id});
                }
                if ( $p_repo ne $p_local ) {
                    push @changed_profiles, [ $profile, $p_local, $p_repo ];
                }
            }
        }
    }

    if ( @changed_profiles ) {
       submit_changed_profiles( \@changed_profiles );
    }
    if ( @new_profiles ) {
       submit_created_profiles( \@new_profiles );
    }
}

sub submit_created_profiles {
    my $new_profiles = shift;
    my $url = $cfg->{repository}{url};

    if ($UI_Mode eq "yast") {
        my $title       = gettext("New profiles");
        my $explanation =
          gettext("Please choose the newly created profiles that you would".
          " like\nto store in the repository");
        yast_select_and_upload_profiles($title,
                                        $explanation,
                                        $new_profiles);
    } else {
        my $title       =
          gettext("Submit newly created profiles to the repository");
        my $explanation =
          gettext("Would you like to upload the newly created profiles?");
        console_select_and_upload_profiles($title,
                                           $explanation,
                                           $new_profiles);
    }
}

sub submit_changed_profiles {
    my $changed_profiles = shift;
    my $url = $cfg->{repository}{url};
    if (@$changed_profiles) {
        if ($UI_Mode eq "yast") {
            my $explanation =
              gettext("Select which of the changed profiles you would".
              " like to upload\nto the repository");
            my $title       = gettext("Changed profiles");
            yast_select_and_upload_profiles($title,
                                            $explanation,
                                            $changed_profiles);
        } else {
            my $title       =
              gettext("Submit changed profiles to the repository");
            my $explanation =
              gettext("The following profiles from the repository were".
              " changed.\nWould you like to upload your changes?");
            console_select_and_upload_profiles($title,
                                               $explanation,
                                               $changed_profiles);
        }
    }
}

sub yast_select_and_upload_profiles {

    my ($title, $explanation, $profiles_ref) = @_;
    my $url = $cfg->{repository}{url};
    my %profile_changes;
    my @profiles = @$profiles_ref;

    foreach my $prof (@profiles) {
        $profile_changes{ $prof->[0] } =
          get_profile_diff($prof->[2], $prof->[1]);
    }

    my (@selected_profiles, $changelog, $changelogs, $single_changelog);
    SendDataToYast(
        {
            type               => "dialog-select-profiles",
            title              => $title,
            explanation        => $explanation,
            default_select     => "false",
            disable_ask_upload => "true",
            profiles           => \%profile_changes
        }
    );
    my ($ypath, $yarg) = GetDataFromYast();
    if ($yarg->{STATUS} eq "cancel") {
        return;
    } else {
        my $selected_profiles_ref = $yarg->{PROFILES};
        @selected_profiles = @$selected_profiles_ref;
        $changelogs        = $yarg->{CHANGELOG};
        if (defined $changelogs->{SINGLE_CHANGELOG}) {
            $changelog        = $changelogs->{SINGLE_CHANGELOG};
            $single_changelog = 1;
        }
    }

    for my $profile (@selected_profiles) {
        my ($user, $pass) = get_repo_user_pass();
        my $profile_string = serialize_profile($sd{$profile}, $profile);
        if (!$single_changelog) {
            $changelog = $changelogs->{$profile};
        }
        my @args = ('Create', $user, $pass, $cfg->{repository}{distro},
                    $profile, $profile_string, $changelog);
        my $res = $repo_client->send_request(@args);
        if (ref $res) {
            my $newprofile = $res->value;
            my $newid      = $newprofile->{id};
            set_repo_info($sd{$profile}{$profile}, $url, $user, $newid);
            writeprofile($profile);
        } else {
            UI_ShortMessage(gettext("Repository Error"),
            "An error occured during the upload of the profile "
            . $profile);
        }
        UI_Info(gettext("Uploaded changes to repository."));
    }

    # Check to see if unselected profiles should be marked as local only
    # this is outside of the main repo code as we want users to be able to mark
    # profiles as local only even if they aren't able to connect to the repo.
    if (defined $yarg->{NEVER_ASK_AGAIN}) {
        my @unselected_profiles;
        foreach my $prof (@profiles) {
            if ( grep(/^$prof->[0]$/, @selected_profiles) == 0 ) {
                push @unselected_profiles, $prof->[0];
            }
        }
        set_profiles_local_only( @unselected_profiles );
    }
}

#
# Mark the profiles passed in @profiles as local only
# and don't prompt to upload changes to the repository
#
sub set_profiles_local_only {
    my @profiles = @_;
    for my $profile (@profiles) {
         $sd{$profile}{$profile}{repo}{neversubmit} = 1;
         writeprofile($profile);
    }
}

sub console_select_and_upload_profiles {
    my ($title, $explanation, $profiles_ref) = @_;
    my $url = $cfg->{repository}{url};
    my @profiles = @$profiles_ref;
    my $q = {};
    $q->{title} = $title;
    $q->{headers} = [ "Repository", $url, ];

    $q->{explanation} = $explanation;

    $q->{functions} = [ "CMD_UPLOAD_CHANGES",
                        "CMD_VIEW_CHANGES",
                        "CMD_ASK_NEVER",
                        "CMD_ABORT", ];

    $q->{default} = "CMD_VIEW_CHANGES";

    $q->{options} = [ map { $_->[0] } @profiles ];
    $q->{selected} = 0;

    my ($ans, $arg);
    do {
        ($ans, $arg) = UI_PromptUser($q);

        if ($ans eq "CMD_VIEW_CHANGES") {
            display_changes($profiles[$arg]->[2], $profiles[$arg]->[1]);
        }
    } until $ans =~ /^CMD_(UPLOAD_CHANGES|ASK_NEVER)/;

    if ($ans eq "CMD_ASK_NEVER") {
        set_profiles_local_only(  map { $_->[0] } @profiles  );
    } elsif ($ans eq "CMD_UPLOAD_CHANGES") {
        my $changelog = UI_GetString(gettext("Changelog Entry: "), "");
        my ($user, $pass) = get_repo_user_pass();
        if ($user && $pass) {
            for my $p_data (@profiles) {
                my $profile        = $p_data->[0];
                my $profile_string = $p_data->[1];
                my @args           = ('Create', $user, $pass,
                                      $cfg->{repository}{distro}, $profile,
                                      $profile_string, $changelog);
                my $res            = $repo_client->send_request(@args);
                if (ref $res) {
                    my $newprofile = $res->value;
                    my $newid      = $newprofile->{id};
                    set_repo_info($sd{$profile}{$profile}, $url, $user, $newid);
                    writeprofile($profile);
                    UI_Info(
                      sprintf(gettext("Uploaded %s to repository."), $profile)
                    );
                } else {
                    print "Error: $res\n";
                }
            }
        } else {
            UI_Important(gettext("Repository Error") . "\n" .  gettext("Registration or Signin was unsuccessful. User login information is required to upload profiles to the repository. These changes have not been sent."));
        }
    }
}

sub get_pager {

    if ( $ENV{PAGER} and (-x "/usr/bin/$ENV{PAGER}" ||
                          -x "/usr/sbin/$ENV{PAGER}" )
       ) {
        return $ENV{PAGER};
    } else {
        return "less"
    }
}


sub display_text {
    my ($header, $body) = @_;
    my $pager = get_pager();
    if (open(PAGER, "| $pager")) {
        print PAGER "$header\n\n$body";
        close(PAGER);
    }
}

sub get_profile_diff {
    my ($oldprofile, $newprofile) = @_;
    my $oldtmp = new File::Temp(UNLINK => 0);
    print $oldtmp $oldprofile;
    close($oldtmp);

    my $newtmp = new File::Temp(UNLINK => 0);
    print $newtmp $newprofile;
    close($newtmp);

    my $difftmp = new File::Temp(UNLINK => 0);
    my @diff;
    system("diff -uw $oldtmp $newtmp > $difftmp");
    while (<$difftmp>) {
        push(@diff, $_) unless (($_ =~ /^(---|\+\+\+)/) ||
                                ($_ =~ /^\@\@.*\@\@$/));
    }
    unlink($difftmp);
    unlink($oldtmp);
    unlink($newtmp);
    return join("", @diff);
}

sub display_changes {
    my ($oldprofile, $newprofile) = @_;

    my $oldtmp = new File::Temp( UNLINK => 0 );
    print $oldtmp $oldprofile;
    close($oldtmp);

    my $newtmp = new File::Temp( UNLINK => 0 );
    print $newtmp $newprofile;
    close($newtmp);

    my $difftmp = new File::Temp(UNLINK => 0);
    my @diff;
    system("diff -uw $oldtmp $newtmp > $difftmp");
    if ($UI_Mode eq "yast") {
        while (<$difftmp>) {
            push(@diff, $_) unless (($_ =~ /^(---|\+\+\+)/) ||
                                    ($_ =~ /^\@\@.*\@\@$/));
        }
        UI_LongMessage(gettext("Profile Changes"), join("", @diff));
    } else {
        system("less $difftmp");
    }

    unlink($difftmp);
    unlink($oldtmp);
    unlink($newtmp);
}

sub setprocess ($$) {
    my ($pid, $profile) = @_;

    # don't do anything if the process exited already...
    return unless -e "/proc/$pid/attr/current";

    return unless open(CURR, "/proc/$pid/attr/current");
    my $current = <CURR>;
    chomp $current;
    close(CURR);

    # only change null profiles
    return unless $current =~ /null(-complain)*-profile/;

    return unless open(STAT, "/proc/$pid/stat");
    my $stat = <STAT>;
    chomp $stat;
    close(STAT);

    return unless $stat =~ /^\d+ \((\S+)\) /;
    my $currprog = $1;

    open(CURR, ">/proc/$pid/attr/current") or return;
    print CURR "setprofile $profile";
    close(CURR);
}

sub collapselog () {
    for my $sdmode (keys %prelog) {
        for my $profile (keys %{ $prelog{$sdmode} }) {
            for my $hat (keys %{ $prelog{$sdmode}{$profile} }) {
                for my $path (keys %{ $prelog{$sdmode}{$profile}{$hat}{path} }) {

                    my $mode = $prelog{$sdmode}{$profile}{$hat}{path}{$path};

                    # we want to ignore anything from the log that's already
                    # in the profile
                    my $combinedmode = "";

                    # is it in the original profile?
                    if ($sd{$profile}{$hat}{path}{$path}) {
                        $combinedmode .= $sd{$profile}{$hat}{path}{$path};
                    }

                    # does path match any regexps in original profile?
                    $combinedmode .= rematchfrag($sd{$profile}{$hat}, $path);

                    # does path match anything pulled in by includes in
                    # original profile?
                    $combinedmode .= matchpathincludes($sd{$profile}{$hat}, $path);

                    # if we found any matching entries, do the modes match?
                    unless ($combinedmode && contains($combinedmode, $mode)) {

                        # merge in any previous modes from this run
                        if ($log{$sdmode}{$profile}{$hat}{path}{$path}) {
                            $mode = collapsemode($mode . $log{$sdmode}{$profile}{$hat}{path}{$path});
                        }

                        # record the new entry
                        $log{$sdmode}{$profile}{$hat}{path}{$path} = collapsemode($mode);
                    }
                }

                for my $capability (keys %{ $prelog{$sdmode}{$profile}{$hat}{capability} }) {

                    # if we don't already have this capability in the profile,
                    # add it
                    unless ($sd{$profile}{$hat}{capability}{$capability}) {
                        $log{$sdmode}{$profile}{$hat}{capability}{$capability} = 1;
                    }
                }

                # Network toggle handling
                my $ndref = $prelog{$sdmode}{$profile}{$hat}{netdomain};
                for my $family ( keys %{$ndref} ) {
                    for my $sock_type ( keys %{$ndref->{$family}} ) {
                        unless ( profile_network_access_check(
                                                              $profile,
                                                              $hat,
                                                              $family,
                                                              $sock_type
                                                             ) ) {
                            $log{$sdmode}
                                {$profile}
                                {$hat}
                                {netdomain}
                                {$family}
                                {$sock_type}=1;
                        }
                    }
                }
            }
        }
    }
}

sub profilemode ($) {
    my $mode = shift;

    my $modifier = ($mode =~ m/[iupUP]/)[0];
    if ($modifier) {
        $mode =~ s/[iupUPx]//g;
        $mode .= $modifier . "x";
    }

    return $mode;
}

# kinky.
sub commonprefix (@) { (join("\0", @_) =~ m/^([^\0]*)[^\0]*(\0\1[^\0]*)*$/)[0] }
sub commonsuffix (@) { reverse(((reverse join("\0", @_)) =~ m/^([^\0]*)[^\0]*(\0\1[^\0]*)*$/)[0]); }

sub uniq (@) {
    my %seen;
    my @result = sort grep { !$seen{$_}++ } @_;
    return @result;
}

our $LOG_MODE_RE = "r|w|l|m|k|a|x|Ix|Px|Ux";
our $PROFILE_MODE_RE = "r|w|l|m|k|a|ix|px|ux|Px|Ux";

sub validate_log_mode ($) {
    my $mode = shift;

    return ($mode =~ /^($LOG_MODE_RE)+$/) ? 1 : 0;
}

sub validate_profile_mode ($) {
    my $mode = shift;

    return ($mode =~ /^($PROFILE_MODE_RE)+$/) ? 1 : 0;
}

sub collapsemode ($) {
    my $old = shift;

    my %seen;
    $seen{$_}++ for ($old =~ m/\G($PROFILE_MODE_RE)/g);

    # "w" implies "a"
    delete $seen{a} if ($seen{w} && $seen{a});

    my $new = join("", sort keys %seen);
    return $new;
}

sub contains ($$) {
    my ($glob, $single) = @_;

    $glob = "" unless defined $glob;

    my %h;
    $h{$_}++ for ($glob =~ m/\G($PROFILE_MODE_RE)/g);

    # "w" implies "a"
    $h{a}++ if $h{w};

    for my $mode ($single =~ m/\G($PROFILE_MODE_RE)/g) {
        return 0 unless $h{$mode};
    }

    return 1;
}

# isSkippableFile - return true if filename matches something that
# should be skipped (rpm backup files, dotfiles, emacs backup files
# Annoyingly, this needs to be kept in sync with the skipped files
# in the apparmor initscript.
sub isSkippableFile($) {
    my $path = shift;

    return ($path =~ /(^|\/)\.[^\/]*$/
            || $path =~ /\.rpm(save|new)$/
            || $path =~ /\.dpkg-(old|new)$/
            || $path =~ /\~$/);
}

sub checkIncludeSyntax($) {
    my $errors = shift;

    if (opendir(SDDIR, $profiledir)) {
        my @incdirs = grep { (!/^\./) && (-d "$profiledir/$_") } readdir(SDDIR);
        close(SDDIR);
        while (my $id = shift @incdirs) {
            if (opendir(SDDIR, "$profiledir/$id")) {
                for my $path (grep { !/^\./ } readdir(SDDIR)) {
                    chomp($path);
                    next if isSkippableFile($path);
                    if (-f "$profiledir/$id/$path") {
                        my $file = "$id/$path";
                        $file =~ s/$profiledir\///;
                        eval { loadinclude($file); };
                        if ( defined $@ && $@ ne "" ) {
                            push @$errors, $@;
                        }
                    } elsif (-d "$id/$path") {
                        push @incdirs, "$id/$path";
                    }
                }
                closedir(SDDIR);
            }
        }
    }
    return $errors;
}

sub checkProfileSyntax ($) {
    my $errors = shift;

    # Check the syntax of profiles

    opendir(SDDIR, $profiledir)
      or fatal_error "Can't read AppArmor profiles in $profiledir.";
    for my $file (grep { -f "$profiledir/$_" } readdir(SDDIR)) {
        next if isSkippableFile($file);
        my $err = readprofile("$profiledir/$file", \&printMessageErrorHandler, 1);
        if (defined $err and $err ne "") {
            push @$errors, $err;
        }
    }
    closedir(SDDIR);
    return $errors;
}

sub printMessageErrorHandler ($) {
    my $message = shift;
    return $message;
}

sub readprofiles () {
    opendir(SDDIR, $profiledir)
      or fatal_error "Can't read AppArmor profiles in $profiledir.";
    for my $file (grep { -f "$profiledir/$_" } readdir(SDDIR)) {
        next if isSkippableFile($file);
        readprofile("$profiledir/$file", \&fatal_error, 1);
    }
    closedir(SDDIR);
}

sub readinactiveprofiles () {
    return if ( ! -e $extraprofiledir );
    opendir(ESDDIR, $extraprofiledir) or
      fatal_error "Can't read AppArmor profiles in $extraprofiledir.";
    for my $file (grep { -f "$extraprofiledir/$_" } readdir(ESDDIR)) {
        next if $file =~ /\.rpm(save|new)|README$/;
        readprofile("$extraprofiledir/$file", \&fatal_error, 0);
    }
    closedir(ESDDIR);
}

sub readprofile ($$$) {
    my $file          = shift;
    my $error_handler = shift;
    my $active_profile = shift;
    if (open(SDPROF, "$file")) {
        local $/;
        my $data = <SDPROF>;
        close(SDPROF);

        eval {
            my $profile_data = parse_profile_data($data, $file);
            if ($profile_data && $active_profile) {
                attach_profile_data(\%sd, $profile_data);
                attach_profile_data(\%original_sd, $profile_data);
            } elsif ( $profile_data ) {
                attach_profile_data(\%extras,      $profile_data);
            }
        };

        # if there were errors loading the profile, call the error handler
        if ($@) {
            $@ =~ s/\n$//;
            return &$error_handler($@);
        }
    } else {
        $DEBUGGING && debug "readprofile: can't read $file - skipping";
    }
}

sub attach_profile_data {
    my ($profiles, $profile_data) = @_;

    # make deep copies of the profile data so that if we change one set of
    # profile data, we're not changing others because of sharing references
    for my $p ( keys %$profile_data) {
          $profiles->{$p} = dclone($profile_data->{$p});
    }
}

sub parse_profile_data {
    my ($data, $file) = @_;


    my ($profile_data, $profile, $hat, $in_contained_hat, $repo_data,
        @parsed_profiles);
    my $initial_comment = "";
    for (split(/\n/, $data)) {
        chomp;

        # we don't care about blank lines
        next if /^\s*$/;

        # start of a profile...
        if (m/^\s*("??\/.+?"??)\s+(flags=\(.+\)\s+)*\{\s*(#.*)?$/) {

            # if we run into the start of a profile while we're already in a
            # profile, something's wrong...
            if ($profile) {
                die "$profile profile in $file contains syntax errors.\n";
            }

            # we hit the start of a profile, keep track of it...
            $profile  = $1;
            my $flags = $2;
            $in_contained_hat = 0;

            # hat is same as profile name if we're not in a hat
            ($profile, $hat) = split /\/\//, $profile;

            # deal with whitespace in profile and hat names.
            $profile = $1 if $profile =~ /^"(.+)"$/;
            $hat     = $1 if $hat && $hat =~ /^"(.+)"$/;

            $hat ||= $profile;

            # keep track of profile flags
            if ($flags && $flags =~ /^flags=\((.+)\)\s*$/) {
                $flags = $1;
                $profile_data->{$profile}{$hat}{flags} = $flags;
            }

            $profile_data->{$profile}{$hat}{netdomain} = { };
            $profile_data->{$profile}{$hat}{path} = { };

            # store off initial comment if they have one
            $profile_data->{$profile}{$hat}{initial_comment} = $initial_comment
              if $initial_comment;
            $initial_comment = "";

            if ($repo_data) {
                $profile_data->{$profile}{$profile}{repo}{url}  = $repo_data->{url};
                $profile_data->{$profile}{$profile}{repo}{user} = $repo_data->{user};
                $profile_data->{$profile}{$profile}{repo}{id}   = $repo_data->{id};
                $repo_data = undef;
            }

        } elsif (m/^\s*\}\s*(#.*)?$/) { # end of a profile...

            # if we hit the end of a profile when we're not in one, something's
            # wrong...
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            if ($in_contained_hat) {
                $hat = $profile;
                $in_contained_hat = 0;
            } else {
                push @parsed_profiles, $profile;
                # mark that we're outside of a profile now...
                $profile = undef;
            }

            $initial_comment = "";

        } elsif (m/^\s*capability\s+(\S+)\s*,\s*(#.*)?$/) {  # capability entry
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            my $capability = $1;
            $profile_data->{$profile}{$hat}{capability}{$capability} = 1;

        } elsif (/^\s*(\$\{?[[:alpha:]][[:alnum:]_]*\}?)\s*=\s*(true|false)\s*(#.*)?$/i) { # boolean definition
        } elsif (/^\s*(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\+=\s*(.+)\s*(#.*)?$/) { # variable additions
        } elsif (/^\s*(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*=\s*(.+)\s*(#.*)?$/) { # variable definitions
        } elsif (m/^\s*if\s+(not\s+)?(\$\{?[[:alpha:]][[:alnum:]_]*\}?)\s*\{\s*(#.*)?$/) { # conditional -- boolean
        } elsif (m/^\s*if\s+(not\s+)?defined\s+(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\{\s*(#.*)?$/) { # conditional -- variable defined
        } elsif (m/^\s*if\s+(not\s+)?defined\s+(\$\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\{\s*(#.*)?$/) { # conditional -- boolean defined
        } elsif (m/^\s*([\"\@\/].*)\s+(\S+)\s*,\s*(#.*)?$/) {     # path entry
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            my ($path, $mode) = ($1, $2);

            # strip off any trailing spaces.
            $path =~ s/\s+$//;

            $path = $1 if $path =~ /^"(.+)"$/;

            # make sure they don't have broken regexps in the profile
            my $p_re = convert_regexp($path);
            eval { "foo" =~ m/^$p_re$/; };
            if ($@) {
                die sprintf(gettext('Profile %s contains invalid regexp %s.'),
                                     $file, $path) . "\n";
            }

            if (!validate_profile_mode($mode)) {
                fatal_error(sprintf(gettext('Profile %s contains invalid mode %s.'), $file, $mode));
            }

            $profile_data->{$profile}{$hat}{path}{$path} = $mode;

        } elsif (m/^\s*#include <(.+)>\s*$/) {     # include stuff
            my $include = $1;

            if ($profile) {
                $profile_data->{$profile}{$hat}{include}{$include} = 1;
            } else {
                unless (exists $variables{$file}) {
                   $variables{$file} = { };
                }
                $variables{$file}{"#" . $include} = 1; # sorry
            }

            # try to load the include...
            my $ret = eval { loadinclude($include); };
            # propagate errors up the chain
            if ($@) { die $@; }

            return $ret if ( $ret != 0 );

        } elsif (/^\s*network/) {
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            unless ($profile_data->{$profile}{$hat}{netdomain}) {
                $profile_data->{$profile}{$hat}{netdomain} = { };
            }

            if ( /^\s*network\s+(\S+)\s*,\s*$/ ) {
                $profile_data->{$profile}{$hat}{netdomain}{$1} = 1;
            } elsif ( /^\s*network\s+(\S+)\s+(\S+)\s*,\s*$/ ) {
                $profile_data->{$profile}{$hat}{netdomain}{$1}{$2} = 1;
            } else {
                $profile_data->{$profile}{$hat}{netdomain}{all} = 1;
            }
        } elsif (/^\s*(tcp_connect|tcp_accept|udp_send|udp_receive)/) {
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            # XXX - BUGBUGBUG - don't strip netdomain entries

            unless ($profile_data->{$profile}{$hat}{netdomain}) {
                $profile_data->{$profile}{$hat}{netdomain} = [ ];
            }

            # strip leading spaces and trailing comma
            s/^\s+//;
            s/,\s*$//;

            # keep track of netdomain entries...
            push @{$profile_data->{$profile}{$hat}{netdomain}}, $_;

        } elsif (m/^\s*\^(\"?.+?)\s+(flags=\(.+\)\s+)*\{\s*(#.*)?$/) {
            # start of a deprecated syntax hat definition
            # read in and mark as changed so that will be written out in the new
            # format

            # if we hit the start of a contained hat when we're not in a profile
            # something is wrong...
            if (not $profile) {
                die sprintf(gettext('%s contains syntax errors.'), $file) . "\n";
            }

            $in_contained_hat = 1;

            # we hit the start of a hat inside the current profile
            $hat = $1;
            my $flags = $2;

            # deal with whitespace in hat names.
            $hat = $1 if $hat =~ /^"(.+)"$/;

            # keep track of profile flags
            if ($flags && $flags =~ /^flags=\((.+)\)\s*$/) {
                $flags = $1;
                $profile_data->{$profile}{$hat}{flags} = $flags;
            }

            $profile_data->{$profile}{$hat}{path} = { };
            $profile_data->{$profile}{$hat}{netdomain} = { };

            # store off initial comment if they have one
            $profile_data->{$profile}{$hat}{initial_comment} = $initial_comment
              if $initial_comment;
            $initial_comment = "";
            # mark as changed so the profile will always be written out
            $changed{$profile} = 1;


        } elsif (/^\s*\#/) {
            # we only currently handle initial comments
            if (not $profile) {
                # ignore vim syntax highlighting lines
                next if /^\s*\# vim:syntax/;
                # ignore Last Modified: lines
                next if /^\s*\# Last Modified:/;
                if (/^\s*\# REPOSITORY: (\S+) (\S+) (\S+)$/) {
                    $repo_data = { url => $1, user => $2, id => $3 };
                } elsif (/^\s*\# REPOSITORY: NEVERSUBMIT$/) {
                    $repo_data = { neversubmit => 1 };
                } else {
                  $initial_comment .= "$_\n";
                }
            }
        } else {
            # we hit something we don't understand in a profile...
            die sprintf(gettext('%s contains syntax errors. Line [%s]'), $file, $_) . "\n";
        }
    }

    #
    # Cleanup : add required hats if not present in the
    #           parsed profiles
    #
    for my $hatglob (keys %{$cfg->{required_hats}}) {
        for my $parsed_profile  ( sort @parsed_profiles )  {
            if ($parsed_profile =~ /$hatglob/) {
                for my $hat (split(/\s+/, $cfg->{required_hats}{$hatglob})) {
                    unless ($profile_data->{$parsed_profile}{$hat}) {
                        $profile_data->{$parsed_profile}{$hat} = { };
                    }
                }
            }
        }
    }

    # if we're still in a profile when we hit the end of the file, it's bad
    if ($profile) {
        die "Reached the end of $file while we were still inside the $profile profile.\n";
    }

    return $profile_data;
}


sub is_active_profile ($) {
    my $pname = shift;
    if ( $sd{$pname} ) {
        return 1;
    }  else {
        return 0;
    }
}

sub escape ($) {
    my $dangerous = shift;

    if ($dangerous =~ m/^"(.+)"$/) {
        $dangerous = $1;
    }
    $dangerous =~ s/((?<!\\))"/$1\\"/g;
    if ($dangerous =~ m/(\s|^$|")/) {
        $dangerous = "\"$dangerous\"";
    }

    return $dangerous;
}

sub writeheader ($$$$) {
    my ($profile_data, $name, $is_hat, $write_flags) = @_;

    my @data;
    # deal with whitespace in profile names...
    $name = "\"$name\"" if $name =~ /\s/;
    push @data, "#include <tunables/global>" unless ( $is_hat );
    if ($write_flags and  $profile_data->{flags}) {
        push @data, "$name flags=($profile_data->{flags}) {";
    } else {
        push @data, "$name {";
    }

    return @data;
}

sub writeincludes ($) {
    my $profile_data = shift;

    my @data;
    # dump out the includes
    if (exists $profile_data->{include}) {
        for my $include (sort keys %{$profile_data->{include}}) {
            push @data, "  #include <$include>";
        }
        push @data, "" if keys %{$profile_data->{include}};
    }

    return @data;
}

sub writecapabilities ($) {
    my $profile_data = shift;

    my @data;
    # dump out the capability entries...
    if (exists $profile_data->{capability}) {
        for my $capability (sort keys %{$profile_data->{capability}}) {
            push @data, "  capability $capability,";
        }
        push @data, "" if keys %{$profile_data->{capability}};
    }

    return @data;
}

sub writenetdomain ($) {
    my $profile_data = shift;

    my @data;
    # dump out the netdomain entries...
    if (exists $profile_data->{netdomain}) {
        if ( $profile_data->{netdomain} == 1 ||
             $profile_data->{netdomain} eq "all") {
            push @data, "  network,";
        } else {
            for my $fam (sort keys %{$profile_data->{netdomain}}) {
                if ( $profile_data->{netdomain}{$fam} == 1 ) {
                    push @data, "  network $fam,";
                } else {
                    for my $type
                        (sort keys %{$profile_data->{netdomain}{$fam}}) {
                        push @data, "  network $fam $type,";
                    }
                }
            }
        }
        push @data, "" if %{$profile_data->{netdomain}};
    }
    return @data;
}

sub writepaths ($) {
    my $profile_data = shift;

    my @data;
    if (exists $profile_data->{path}) {
        for my $path (sort keys %{$profile_data->{path}}) {
            my $mode = $profile_data->{path}{$path};

            # strip out any fake access() modes that might have slipped through
            $mode =~ s/X//g;

            # deal with whitespace in path names
            if ($path =~ /\s/) {
                push @data, "  \"$path\" $mode,";
            } else {
                push @data, "  $path $mode,";
            }
        }
    }

    return @data;
}

sub writepiece ($$$) {
    my ($profile_data, $name, $write_flags) = @_;

    my @data;
    push @data, writeheader($profile_data->{$name}, $name, 0, $write_flags);
    push @data, writeincludes($profile_data->{$name});
    push @data, writecapabilities($profile_data->{$name});
    push @data, writenetdomain($profile_data->{$name});
    push @data, writepaths($profile_data->{$name});
    push @data, "}";

    for my $hat (grep { $_ ne $name } sort keys %{$profile_data}) {
        push @data, "";
        push @data, map { "  $_" } writeheader($profile_data->{$hat},
                                               "$name//$hat",
                                               1,
                                               $write_flags);
        push @data, map { "  $_" } writeincludes($profile_data->{$hat});
        push @data, map { "  $_" } writecapabilities($profile_data->{$hat});
        push @data, map { "  $_" } writenetdomain($profile_data->{$hat});
        push @data, map { "  $_" } writepaths($profile_data->{$hat});
        push @data, "  }";
    }

    return @data;
}

sub serialize_profile {
    my ($profile_data, $name, $options) = @_;

    my $string = "";
    my $include_metadata = 0;  # By default don't write out metadata
    my $include_flags = 1;
    if ( $options and ref($options) eq "HASH" ) {
       $include_metadata = 1 if ( defined $options->{METADATA} );
       $include_flags    = 0 if ( defined $options->{NO_FLAGS} );
    }

    if ($include_metadata) {
        # keep track of when the file was last updated
        $string .= "# Last Modified: " . localtime(time) . "\n";

        # print out repository metadata
        if ($profile_data->{$name}{repo}       &&
            $profile_data->{$name}{repo}{url}  &&
            $profile_data->{$name}{repo}{user} &&
            $profile_data->{$name}{repo}{id}) {
            my $repo = $profile_data->{$name}{repo};
            $string .= "# REPOSITORY: $repo->{url} $repo->{user} $repo->{id}\n";
        } elsif ($profile_data->{$name}{repo}{neversubmit}) {
            $string .= "# REPOSITORY: NEVERSUBMIT\n";
        }
    }

    # print out initial comment
    if ($profile_data->{$name}{initial_comment}) {
        my $comment = $profile_data->{$name}{initial_comment};
        $comment =~ s/\\n/\n/g;
        $string .= "$comment\n";
    }

# XXX - FIXME
#
#  # dump variables defined in this file
#  if ($variables{$filename}) {
#    for my $var (sort keys %{$variables{$filename}}) {
#      if ($var =~ m/^@/) {
#        my @values = sort @{$variables{$filename}{$var}};
#        @values = map { escape($_) } @values;
#        my $values = join (" ", @values);
#        print SDPROF "$var = ";
#        print SDPROF $values;
#      } elsif ($var =~ m/^\$/) {
#        print SDPROF "$var = ";
#        print SDPROF ${$variables{$filename}{$var}};
#      } elsif ($var =~ m/^\#/) {
#        my $inc = $var;
#        $inc =~ s/^\#//;
#        print SDPROF "#include <$inc>";
#      }
#      print SDPROF "\n";
#    }
#  }

    $string .= join("\n", writepiece($profile_data, $name, $include_flags));

    return "$string\n";
}

sub writeprofile ($) {
    my $profile = shift;

    UI_Info(sprintf(gettext('Writing updated profile for %s.'), $profile));

    my $filename = getprofilefilename($profile);

    open(SDPROF, ">$filename") or
      fatal_error "Can't write new AppArmor profile $filename: $!";
    my $serialize_opts = { };
    $serialize_opts->{METADATA} = 1;
    my $profile_string = serialize_profile($sd{$profile}, $profile, $serialize_opts);
    print SDPROF $profile_string;
    close(SDPROF);

    # mark the profile as up-to-date
    delete $changed{$profile};
    $original_sd{$profile} = dclone($sd{$profile});
}

sub getprofileflags {
    my $filename = shift;

    my $flags = "enforce";

    if (open(PROFILE, "$filename")) {
        while (<PROFILE>) {
            if (m/^\s*\/\S+\s+(flags=\(.+\)\s+)*{\s*$/) {
                $flags = $1;
                close(PROFILE);
                $flags =~ s/flags=\((.+)\)/$1/;
                return $flags;
            }
        }
        close(PROFILE);
    }

    return $flags;
}


sub matchliteral {
    my ($sd_regexp, $literal) = @_;

    my $p_regexp = convert_regexp($sd_regexp);

    # check the log entry against our converted regexp...
    my $matches = eval { $literal =~ /^$p_regexp$/; };

    # doesn't match if we've got a broken regexp
    return undef if $@;

    return $matches;
}

sub profile_exec_access_check ($$$$) {
    my ($profile, $hat, $type, $exec_target) = @_;
    if ( $type eq "exec" ) {
        my ($combinedmode, $cm, @m);

        # does path match any regexps in original profile?
        ($cm, @m) = rematchfrag($sd{$profile}{$hat}, $exec_target);
        $combinedmode .= $cm if $cm;

        # does path match anything pulled in by includes in
        # original profile?
        ($cm, @m) = matchpathincludes($sd{$profile}{$hat}, $exec_target);
        $combinedmode .= $cm if $cm;

        if (contains($combinedmode, "ix") ||
            contains($combinedmode, "px") ||
            contains($combinedmode, "ux") ||
            contains($combinedmode, "Px") ||
            contains($combinedmode, "Ux")) {
            return 1;
        }
    }
    return 0;
}

sub profile_capability_access_check ($$$) {
    my ($profile, $hat, $capname) = @_;
    for my $incname ( keys %{$sd{$profile}{$hat}{include}} ) {
        return 1 if $include{$incname}{capability}{$capname};
    }
    return 1 if $sd{$profile}{$hat}{capability}{$capname};
    return 0;
}

sub profile_network_access_check ($$$$) {
    my ($profile, $hat, $family, $sock_type) = @_;

    for my $incname ( keys %{$sd{$profile}{$hat}{include}} ) {
        return 1 if netrules_access_check( $include{$incname}{netdomain},
                                           $family,
                                           $sock_type
                                         );
    }
    return 1 if netrules_access_check( $sd{$profile}{$hat}{netdomain},
                                       $family,
                                       $sock_type
                                     );
    return 0;
}

sub netrules_access_check ($$$) {
    my ($netrules, $family, $sock_type) = @_;
    return 0 if ( not defined $netrules );
    my %netrules        = %$netrules;;
    my $all_net         = defined $netrules{all};
    my $all_net_family  = defined $netrules{$family} && $netrules{$family} == 1;
    my $net_family_sock = defined $netrules{$family} &&
                          ref($netrules{$family}) eq "HASH" &&
                          defined $netrules{$family}{$sock_type};

    if ( $all_net || $all_net_family || $net_family_sock ) {
        return 1;
    } else {
      return 0;
    }
}

sub reload ($) {
    my $bin = shift;

    # don't try to reload profile if AppArmor is not running
    return unless check_for_subdomain();

    # don't reload the profile if the corresponding executable doesn't exist
    my $fqdbin = findexecutable($bin) or return;

    my $filename = getprofilefilename($fqdbin);

    system("/bin/cat '$filename' | $parser -I$profiledir -r >/dev/null 2>&1");
}

sub read_include_from_file {
    my $which = shift;

    my $data;
    if (open(INCLUDE, "$profiledir/$which")) {
        local $/;
        $data = <INCLUDE>;
        close(INCLUDE);
    }

    return $data;
}

sub get_include_data {
    my $which = shift;

    my $data = read_include_from_file($which);
    unless($data) {
        fatal_error "Can't find include file $which: $!";
    }
    return $data;
}

sub loadinclude {
    my $which = shift;

    # don't bother loading it again if we already have
    return 0 if $include{$which};

    my @loadincludes = ($which);
    while (my $incfile = shift @loadincludes) {

        my $data = get_include_data($incfile);
        for (split(/\n/, $data)) {
            chomp;

            if (/^\s*(\$\{?[[:alpha:]][[:alnum:]_]*\}?)\s*=\s*(true|false)\s*$/i) {
                # boolean definition
            } elsif (/^\s*(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\+=\s*(.+)\s*$/) {
                # variable additions
            } elsif (/^\s*(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*=\s*(.+)\s*$/) {
                # variable definitions
            } elsif (m/^\s*if\s+(not\s+)?(\$\{?[[:alpha:]][[:alnum:]_]*\}?)\s*\{\s*$/) {
                # conditional -- boolean
            } elsif (m/^\s*if\s+(not\s+)?defined\s+(@\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\{\s*$/) {
                # conditional -- variable defined
            } elsif (m/^\s*if\s+(not\s+)?defined\s+(\$\{?[[:alpha:]][[:alnum:]_]+\}?)\s*\{\s*$/) {
                # conditional -- boolean defined
            } elsif (m/^\s*\}\s*$/) {
                # end of a profile or conditional
            } elsif (m/^\s*([\"\@\/].*)\s+(\S+)\s*,\s*$/) {
                # path entry

                my ($path, $mode) = ($1, $2);

                # strip off any trailing spaces.
                $path =~ s/\s+$//;

                $path = $1 if $path =~ /^"(.+)"$/;

                # make sure they don't have broken regexps in the profile
                my $p_re = convert_regexp($path);
                eval { "foo" =~ m/^$p_re$/; };
                if ($@) {
                    die sprintf(gettext('Include file %s contains invalid regexp %s.'),
                                        $incfile, $path) . "\n";
                }

                if (!validate_profile_mode($mode)) {
                    fatal_error(sprintf(gettext('Include file %s contains invalid mode %s.'), $incfile, $mode));
                }

                $include{$incfile}{path}{$path} = $mode;
            } elsif (/^\s*capability\s+(.+)\s*,\s*$/) {

                my $capability = $1;
                $include{$incfile}{capability}{$capability} = 1;

            } elsif (/^\s*#include <(.+)>\s*$/) {
                # include stuff

                my $newinclude = $1;
                push @loadincludes, $newinclude unless $include{$newinclude};
                $include{$incfile}{include}{$newinclude} = 1;

            } elsif (/^\s*(tcp_connect|tcp_accept|udp_send|udp_receive)/) {
            } elsif (/^\s*network/) {
                if ( /^\s*network\s+(\S+)\s*,\s*$/ ) {
                    $include{$incfile}{netdomain}{$1} = 1;
                } elsif ( /^\s*network\s+(\S+)\s+(\S+)\s*,\s*$/ ) {
                    $include{$incfile}{netdomain}{$1}{$2} = 1;
                } else {
                    $include{$incfile}{netdomain}{all} = 1;
                }
            } else {

                # we don't care about blank lines or comments
                next if /^\s*$/;
                next if /^\s*\#/;

                # we hit something we don't understand in a profile...
                die sprintf(gettext('Include file %s contains syntax errors or is not a valid #include file.'), $incfile) . "\n";
            }
        }
        close(INCLUDE);
    }

    return 0;
}

sub rematchfrag {
    my ($frag, $path) = @_;

    my $combinedmode = "";
    my @matches;

    for my $entry (keys %{ $frag->{path} }) {

        my $regexp = convert_regexp($entry);

        # check the log entry against our converted regexp...
        if ($path =~ /^$regexp$/) {

            # regexp matches, add it's mode to the list to check against
            $combinedmode .= $frag->{path}{$entry};
            push @matches, $entry;
        }
    }

    return wantarray ? ($combinedmode, @matches) : $combinedmode;
}

sub matchpathincludes {
    my ($frag, $path) = @_;

    my $combinedmode = "";
    my @matches;

    # scan the include fragments for this profile looking for matches
    my @includelist = keys %{ $frag->{include} };
    while (my $include = shift @includelist) {
        my $ret = eval { loadinclude($include); };
        if ($@) { fatal_error $@; }
        my ($cm, @m) = rematchfrag($include{$include}, $path);
        if ($cm) {
            $combinedmode .= $cm;
            push @matches, @m;
        }

        # check if a literal version is in the current include fragment
        if ($include{$include}{path}{$path}) {
            $combinedmode .= $include{$include}{path}{$path};
        }

        # if this fragment includes others, check them too
        if (keys %{ $include{$include}{include} }) {
            push @includelist, keys %{ $include{$include}{include} };
        }
    }

    return wantarray ? ($combinedmode, @matches) : $combinedmode;
}

sub matchpathinclude {
    my ($incname, $path) = @_;

    my $combinedmode = "";
    my @matches;

    # scan the include fragments for this profile looking for matches
    my @includelist = ($incname);
    while (my $include = shift @includelist) {
        my ($cm, @m) = rematchfrag($include{$include}, $path);
        if ($cm) {
            $combinedmode .= $cm;
            push @matches, @m;
        }

        # check if a literal version is in the current include fragment
        if ($include{$include}{path}{$path}) {
            $combinedmode .= $include{$include}{path}{$path};
        }

        # if this fragment includes others, check them too
        if (keys %{ $include{$include}{include} }) {
            push @includelist, keys %{ $include{$include}{include} };
        }
    }

    if ($combinedmode) {
        return wantarray ? ($combinedmode, @matches) : $combinedmode;
    } else {
        return;
    }
}

sub check_qualifiers {
    my $program = shift;

    if ($cfg->{qualifiers}{$program}) {
        unless($cfg->{qualifiers}{$program} =~ /p/) {
            fatal_error(sprintf(gettext("\%s is currently marked as a program that should not have it's own profile.  Usually, programs are marked this way if creating a profile for them is likely to break the rest of the system.  If you know what you're doing and are certain you want to create a profile for this program, edit the corresponding entry in the [qualifiers] section in /etc/apparmor/logprof.conf."), $program));
        }
    }
}

sub read_config {
    my $filename = shift;
    my $config;

    if (open(CONF, "$confdir/$filename")) {
        my $which;
        while (<CONF>) {
            chomp;
            # ignore comments
            next if /^\s*#/;
            if (m/^\[(\S+)\]/) {
                $which = $1;
            } elsif (m/^\s*(\S+)\s*=\s*(.*)\s*$/) {
                my ($key, $value) = ($1, $2);
                $config->{$which}{$key} = $value;
            }
        }
        close(CONF);
    }

    return $config;
}

sub write_config {
    my ($filename, $config) = @_;
    if (open(my $CONF, ">$confdir/$filename")) {
        for my $section (sort keys %$config) {
            print $CONF "[$section]\n";

            for my $key (sort keys %{$config->{$section}}) {
                print $CONF "  $key = $config->{$section}{$key}\n"
                    if ($config->{$section}{$key});
            }
        }
        chmod(0600, $CONF);
        close($CONF);
    } else {
        fatal_error "Can't write config file $filename: $!";
    }
}

sub find_first_file {
    my $list = shift;
    return if ( not defined $list );
    my $filename;
    for my $f (split(/\s+/, $list)) {
        if (-f $f) {
            $filename = $f;
            last;
        }
    }

    return $filename;
}

sub find_first_dir {
    my $list = shift;
    return if ( not defined $list );
    my $dirname;
    for my $f (split(/\s+/, $list)) {
        if (-d $f) {
            $dirname = $f;
            last;
        }
    }

    return $dirname;
}

sub loadincludes {
    if (opendir(SDDIR, $profiledir)) {
        my @incdirs = grep { (!/^\./) && (-d "$profiledir/$_") } readdir(SDDIR);
        close(SDDIR);

        while (my $id = shift @incdirs) {
            if (opendir(SDDIR, "$profiledir/$id")) {
                for my $path (readdir(SDDIR)) {
                    chomp($path);
                    next if isSkippableFile($path);
                    if (-f "$profiledir/$id/$path") {
                        my $file = "$id/$path";
                        $file =~ s/$profiledir\///;
                        my $ret = eval { loadinclude($file); };
                        if ($@) { fatal_error $@; }
                    } elsif (-d "$id/$path") {
                        push @incdirs, "$id/$path";
                    }
                }
                closedir(SDDIR);
            }
        }
    }
}

sub globcommon ($) {
    my $path = shift;

    my @globs;

    # glob library versions in both foo-5.6.so and baz.so.9.2 form
    if ($path =~ m/[\d\.]+\.so$/ || $path =~ m/\.so\.[\d\.]+$/) {
        my $libpath = $path;
        $libpath =~ s/[\d\.]+\.so$/*.so/;
        $libpath =~ s/\.so\.[\d\.]+$/.so.*/;
        push @globs, $libpath if $libpath ne $path;
    }

    for my $glob (keys %{$cfg->{globs}}) {
        if ($path =~ /$glob/) {
            my $globbedpath = $path;
            $globbedpath =~ s/$glob/$cfg->{globs}{$glob}/g;
            push @globs, $globbedpath if $globbedpath ne $path;
        }
    }

    if (wantarray) {
        return sort { length($b) <=> length($a) } uniq(@globs);
    } else {
        my @list = sort { length($b) <=> length($a) } uniq(@globs);
        return $list[$#list];
    }
}

# this is an ugly, nasty function that attempts to see if one regexp
# is a subset of another regexp
sub matchregexp ($$) {
    my ($new, $old) = @_;

    # bail out if old pattern has {foo,bar,baz} stuff in it
    return undef if $old =~ /\{.*(\,.*)*\}/;

    # are there any regexps at all in the old pattern?
    if ($old =~ /\[.+\]/ or $old =~ /\*/ or $old =~ /\?/) {

        # convert {foo,baz} to (foo|baz)
        $new =~ y/\{\}\,/\(\)\|/ if $new =~ /\{.*\,.*\}/;

        # \001 == SD_GLOB_RECURSIVE
        # \002 == SD_GLOB_SIBLING

        $new =~ s/\*\*/\001/g;
        $new =~ s/\*/\002/g;

        $old =~ s/\*\*/\001/g;
        $old =~ s/\*/\002/g;

        # strip common prefix
        my $prefix = commonprefix($new, $old);
        if ($prefix) {

            # make sure we don't accidentally gobble up a trailing * or **
            $prefix =~ s/(\001|\002)$//;
            $new    =~ s/^$prefix//;
            $old    =~ s/^$prefix//;
        }

        # strip common suffix
        my $suffix = commonsuffix($new, $old);
        if ($suffix) {

            # make sure we don't accidentally gobble up a leading * or **
            $suffix =~ s/^(\001|\002)//;
            $new    =~ s/$suffix$//;
            $old    =~ s/$suffix$//;
        }

        # if we boiled the differences down to a ** in the new entry, it matches
        # whatever's in the old entry
        return 1 if $new eq "\001";

        # if we've paired things down to a * in new, old matches if there are no
        # slashes left in the path
        return 1 if ($new eq "\002" && $old =~ /^[^\/]+$/);

        # we'll bail out if we have more globs in the old version
        return undef if $old =~ /\001|\002/;

        # see if we can match * globs in new against literal elements in old
        $new =~ s/\002/[^\/]*/g;

        return 1 if $old =~ /^$new$/;

    } else {

        my $new_regexp = convert_regexp($new);

        # check the log entry against our converted regexp...
        return 1 if $old =~ /^$new_regexp$/;

    }

    return undef;
}

sub combine_name($$) { return ($_[0] eq $_[1]) ? $_[0] : "$_[0]^$_[1]"; }
sub split_name ($) { my ($p, $h) = split(/\^/, $_[0]); $h ||= $p; ($p, $h); }

##########################
#
# prompt_user($headers, $functions, $default, $options, $selected);
#
# $headers:
#   a required arrayref made up of "key, value" pairs in the order you'd
#   like them displayed to user
#
# $functions:
#   a required arrayref of the different options to display at the bottom
#   of the prompt like "(A)llow", "(D)eny", and "Ba(c)on".  the character
#   contained by ( and ) will be used as the key to select the specified
#   option.
#
# $default:
#   a required character which is the default "key" to enter when they
#   just hit enter
#
# $options:
#   an optional arrayref of the choices like the glob suggestions to be
#   presented to the user
#
# $selected:
#   specifies which option is currently selected
#
# when prompt_user() is called without an $options list, it returns a
# single value which is the key for the specified "function".
#
# when prompt_user() is called with an $options list, it returns an array
# of two elements, the key for the specified function as well as which
# option was currently selected
#######################################################################

sub Text_PromptUser ($) {
    my $question = shift;

    my $title     = $question->{title};
    my $explanation = $question->{explanation};

    my @headers   = (@{ $question->{headers} });
    my @functions = (@{ $question->{functions} });

    my $default  = $question->{default};
    my $options  = $question->{options};
    my $selected = $question->{selected} || 0;

    my $helptext = $question->{helptext};

    push @functions, "CMD_HELP" if $helptext;

    my %keys;
    my @menu_items;
    for my $cmd (@functions) {

        # make sure we know about this particular command
        my $cmdmsg = "PromptUser: " . gettext("Unknown command") . " $cmd";
        fatal_error $cmdmsg unless $CMDS{$cmd};

        # grab the localized text to use for the menu for this command
        my $menutext = gettext($CMDS{$cmd});

        # figure out what the hotkey for this menu item is
        my $menumsg = "PromptUser: " .
                      gettext("Invalid hotkey in") .
                      " '$menutext'";
        $menutext =~ /\((\S)\)/ or fatal_error $menumsg;

        # we want case insensitive comparisons so we'll force things to
        # lowercase
        my $key = lc($1);

        # check if we're already using this hotkey for this prompt
        my $hotkeymsg = "PromptUser: " .
                        gettext("Duplicate hotkey for") .
                        " $cmd: $menutext";
        fatal_error $hotkeymsg if $keys{$key};

        # keep track of which command they're picking if they hit this hotkey
        $keys{$key} = $cmd;

        if ($default && $default eq $cmd) {
            $menutext = "[$menutext]";
        }

        push @menu_items, $menutext;
    }

    # figure out the key for the default option
    my $default_key;
    if ($default && $CMDS{$default}) {
        my $defaulttext = gettext($CMDS{$default});

        # figure out what the hotkey for this menu item is
        my $defmsg = "PromptUser: " .
                      gettext("Invalid hotkey in default item") .
                      " '$defaulttext'";
        $defaulttext =~ /\((\S)\)/ or fatal_error $defmsg;

        # we want case insensitive comparisons so we'll force things to
        # lowercase
        $default_key = lc($1);

        my $defkeymsg = "PromptUser: " .
                        gettext("Invalid default") .
                        " $default";
        fatal_error $defkeymsg unless $keys{$default_key};
    }

    my $widest = 0;
    my @poo    = @headers;
    while (my $header = shift @poo) {
        my $value = shift @poo;
        $widest = length($header) if length($header) > $widest;
    }
    $widest++;

    my $format = '%-' . $widest . "s \%s\n";

    my $function_regexp = '^(';
    $function_regexp .= join("|", keys %keys);
    $function_regexp .= '|\d' if $options;
    $function_regexp .= ')$';

    my $ans = "XXXINVALIDXXX";
    while ($ans !~ /$function_regexp/i) {
        # build up the prompt...
        my $prompt = "\n";

        $prompt .= "= $title =\n\n" if $title;

        if (@headers) {
            my @poo = @headers;
            while (my $header = shift @poo) {
                my $value = shift @poo;
                $prompt .= sprintf($format, "$header:", $value);
            }
            $prompt .= "\n";
        }

        if ($explanation) {
            $prompt .= "$explanation\n\n";
        }

        if ($options) {
            for (my $i = 0; $options->[$i]; $i++) {
                my $f = ($selected == $i) ? ' [%d - %s]' : '  %d - %s ';
                $prompt .= sprintf("$f\n", $i + 1, $options->[$i]);
            }
            $prompt .= "\n";
        }
        $prompt .= join(" / ", @menu_items);
        print "$prompt\n";

        # get their input...
        $ans = lc(getkey());

        if ($ans) {
            # handle escape sequences so you can up/down in the list
            if ($ans eq "up") {

                if ($options && ($selected > 0)) {
                    $selected--;
                }
                $ans = "XXXINVALIDXXX";

            } elsif ($ans eq "down") {

                if ($options && ($selected < (scalar(@$options) - 1))) {
                    $selected++;
                }
                $ans = "XXXINVALIDXXX";

            } elsif ($keys{$ans} && $keys{$ans} eq "CMD_HELP") {

                print "\n$helptext\n";
                $ans = "XXXINVALIDXXX";

            } elsif (ord($ans) == 10) {

                # pick the default if they hit return...
                $ans = $default_key;

            } elsif ($options && ($ans =~ /^\d$/)) {

                # handle option poo
                if ($ans > 0 && $ans <= scalar(@$options)) {
                    $selected = $ans - 1;
                }
                $ans = "XXXINVALIDXXX";
            }
        }

        if ($keys{$ans} && $keys{$ans} eq "CMD_HELP") {
            print "\n$helptext\n";
            $ans = "again";
        }
    }

    # pull our command back from our hotkey map
    $ans = $keys{$ans} if $keys{$ans};
    return ($ans, $selected);

}

###############################################################################
# required initialization

$cfg = read_config("logprof.conf");

eval "use RPC::XML";
if (!$@) {
    eval "use RPC::XML::Client";
    if (!$@) {
        $is_rpc_xml = 1;
    } else {
        $is_rpc_xml = 0;
    }
} else {
    $is_rpc_xml = 0;
    if ($repo_cfg &&
        $repo_cfg->{repository}{enabled} &&
        $repo_cfg->{repository}{enabled} eq "yes") {
#hmm log message that repository is disabled because rpc-xml is not found
#or abort with message to disable repository or install rpc-xml
    }
}

$profiledir = find_first_dir($cfg->{settings}{profiledir}) || "/etc/apparmor.d";
unless (-d $profiledir) { fatal_error "Can't find AppArmor profiles."; }

$extraprofiledir = find_first_dir($cfg->{settings}{inactive_profiledir}) ||
"/etc/apparmor/profiles/extras/";

$parser = find_first_file($cfg->{settings}{parser}) || "/sbin/apparmor_parser";
unless (-x $parser) { fatal_error "Can't find apparmor_parser."; }

$filename = find_first_file($cfg->{settings}{logfiles}) || "/var/log/messages";
unless (-f $filename) { fatal_error "Can't find system log."; }

$ldd = find_first_file($cfg->{settings}{ldd}) || "/usr/bin/ldd";
unless (-x $ldd) { fatal_error "Can't find ldd."; }

$logger = find_first_file($cfg->{settings}{logger}) || "/bin/logger";
unless (-x $logger) { fatal_error "Can't find logger."; }

1;

