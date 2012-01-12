#! /usr/bin/perl -w
#
# mkprofile.pl -
#   generate a formatted profile based on passed in arguments
#
# Gawd, I hate writing perl. It shows, too.
#
my $__VERSION__=$0;

use strict;
use Getopt::Long;
use Cwd 'realpath';

my $help = '';
my $nowarn = '';
my $nodefault;
my $escape = '';
my %output_rules;
my $hat = "__no_hat";
my %flags;

GetOptions(
  'escape|E' => \$escape,
  'nowarn' => \$nowarn,
  'help|h' => \$help,
  'nodefault|N' => \$nodefault,
);

sub usage {
  print STDERR "$__VERSION__\n";
  print STDERR "Usage $0 [--nowarn|--escape] execname [rules]\n";
  print STDERR "      $0 --help\n";
  print STDERR "  nowarn:      don't warn if execname does not exist\n";
  print STDERR "  nodefault:   don't include default rules/ldd output\n";
  print STDERR "  escape:      escape stuff that would be treated as regexs\n";
  print STDERR "  help:        print this message\n";
}

&usage && exit 0 if ($help || @ARGV < 1);

sub head ($) {
  my $file = shift;

  my $first = "";
  if (open(FILE, $file)) {
    $first = <FILE>;
    close(FILE);
  }

  return $first;
}

sub get_output ($@) {
  my ($program, @args) = @_;

  my $ret = -1;

  my $pid;
  my @output;

  if (-x $program) {
    $pid = open(KID_TO_READ, "-|");
    unless (defined $pid) {
      die "can't fork: $!";
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
        || die "can't dup stdout to stderr";
      exec($program, @args) || die "can't exec program: $!";

      # NOTREACHED
    }
  }

  return ($ret, @output);
}

sub gen_default_rules() {
  gen_file("/etc/ld.so.cache:r");

  # give every profile access to change_hat
  gen_file("/proc/*/attr/current:w");

  # give every profile access to /dev/urandom (propolice, etc.)
  gen_file("/dev/urandom:r");
}

sub gen_elf_binary($) {
  my $bin = shift;

  my ($ret, @ldd) = get_output("/usr/bin/ldd", $bin);
  if ($ret == 0) {
    for my $line (@ldd) {
      last if $line =~ /not a dynamic executable/;
      last if $line =~ /cannot read header/;
      last if $line =~ /statically linked/;

      # avoid new kernel 2.6 poo
      next if $line =~ /linux-(gate|vdso(32|64)).so/;

      if ($line =~ /^\s*\S+ => (\/\S+)/) {
        # shared libraries
        gen_file(realpath($1) . ":mr")
      } elsif ($line =~ /^\s*(\/\S+)/) {
        # match loader lines like "/lib64/ld-linux-x86-64.so.2 (0x00007fbb46999000)"
        gen_file(realpath($1) . ":rix")
      }
    }
  }
}

sub gen_binary($) {
  my $bin = shift;

  gen_file("$bin:r");

  my $hashbang = head($bin);
  if ($hashbang && $hashbang =~ /^#!\s*(\S+)/) {
    my $interpreter = $1;
    gen_file("$interpreter:rix");
    gen_elf_binary($interpreter);
  } else {
    gen_elf_binary($bin)
  }
}

sub gen_netdomain($) {
  my $rule = shift;
  # only split on single ':'s
  my @rules = split (/(?<!:):(?!:)/, $rule);
  # convert '::' to ':' -- for port designations
  foreach (@rules) { s/::/:/g; }
  push (@{$output_rules{$hat}}, "  @rules,\n");
}

sub gen_network($) {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  push (@{$output_rules{$hat}}, "  @rules,\n");
}

sub gen_cap($) {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid capability description '$rule', ignored\n";
  } else {
    push (@{$output_rules{$hat}}, "  capability $rules[1],\n");
  }
}

sub gen_file($) {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  # default: file rules
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid file access '$rule', ignored\n";
  } else {
    if ($escape) {
      $rules[0]=~ s/(["[\]{}\\\:\#])/\\$1/g;
      $rules[0]=~ s/(\#)/\\043/g;
    }
    if ($rules[0]=~ /[\s\!\"\^]/) {
      push (@{$output_rules{$hat}}, "  \"$rules[0]\" $rules[1],\n");
    } else {
      push (@{$output_rules{$hat}}, "  $rules[0] $rules[1],\n");
    }
  }
}

sub gen_flag($) {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid flag description '$rule', ignored\n";
  } else {
    push (@{$flags{$hat}},$rules[1]);
  }
}

sub gen_hat($) {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid hat description '$rule', ignored\n";
  } else {
    $hat = $rules[1];
    # give every profile/hat access to change_hat
    @{$output_rules{$hat}} = ( "  /proc/*/attr/current w,\n",);
  }
}

my $bin = shift @ARGV;
!(-e $bin || $nowarn) && print STDERR "Warning: execname '$bin': no such file or directory\n";

unless ($nodefault) {
  gen_default_rules();
  gen_binary($bin);
}

for my $rule (@ARGV) {
  #($fn, @rules) = split (/:/, $rule);
  if ($rule =~ /^(tcp|udp)/) {
    # netdomain rules
    gen_netdomain($rule);
  } elsif ($rule =~ /^network:/) {
    gen_network($rule);
  } elsif ($rule =~ /^cap:/) {
    gen_cap($rule);
  } elsif ($rule =~ /^flag:/) {
    gen_flag($rule);
  } elsif ($rule =~ /^hat:/) {
    gen_hat($rule);
  } else {
    gen_file($rule);
  }
}

sub emit_flags($) {
  my $hat = shift;

  if (exists $flags{$hat}) {
    print STDOUT " flags=(";
    print STDOUT pop(@{$flags{$hat}});
    foreach my $flag (@{$flags{$hat}}) {
      print STDOUT ", $flag";
    }
    print STDOUT ") ";
  }
}

print STDOUT "# Profile autogenerated by $__VERSION__\n";
print STDOUT "$bin ";
emit_flags('__no_hat');
print STDOUT "{\n";
foreach my $outrule (@{$output_rules{'__no_hat'}}) {
  print STDOUT $outrule;
}
foreach my $hat (keys %output_rules) {
  if (not $hat =~ /^__no_hat$/) {
    print STDOUT "\n  ^$hat";
    emit_flags($hat);
    print STDOUT " {\n";
    foreach my $outrule (@{$output_rules{$hat}}) {
      print STDOUT "  $outrule";
    }
    print STDOUT "  }\n";
  }
}
#foreach my $hat keys
#foreach my $outrule (@output_rules) {
#  print STDOUT $outrule;
#}
print STDOUT "}\n";
