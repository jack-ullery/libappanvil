#! /usr/bin/perl -w
#
# mkprofile.pl -
#   generate a formatted profile based on passed in arguments
#
# Gawd, I hate writing perl. It shows, too.
#
my $__VERSION__='$Id: mkprofile.pl 5923 2005-12-14 18:49:16Z steve $';

use strict;
use Getopt::Long;

my $help = '';
my $nowarn = '';
my $escape = '';
my %output_rules;
my $hat = "__no_hat";
my %flags;

GetOptions(
  'escape|E' => \$escape,
  'nowarn' => \$nowarn,
  'help|h' => \$help,
);

sub usage {
  print STDERR "$__VERSION__\n";
  print STDERR "Usage $0 [--nowarn|--escape] execname [rules]\n";
  print STDERR "      $0 --help\n";
  print STDERR "  nowarn:      don't warn if execname does not exist\n";
  print STDERR "  escape:      escape stuff that would be treated as regexs\n";
  print STDERR "  help:        print this message\n";
}

&usage && exit 0 if ($help || @ARGV < 1); 

sub emit_netdomain {
  my $rule = shift;
  # only split on single ':'s
  my @rules = split (/(?<!:):(?!:)/, $rule);
  # convert '::' to ':' -- for port designations
  foreach (@rules) { s/::/:/g; }
  push (@{$output_rules{$hat}}, "  @rules,\n");
}

sub emit_cap {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid capability description '$rule', ignored\n";
  } else {
    push (@{$output_rules{$hat}}, "  capability $rules[1],\n");
  }
}

sub emit_file {
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

sub emit_flag {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid flag description '$rule', ignored\n";
  } else {
    push (@{$flags{$hat}},$rules[1]);
  }
}

sub emit_hat {
  my $rule = shift;
  my @rules = split (/:/, $rule);
  if (@rules != 2) {
    (!$nowarn) && print STDERR "Warning: invalid hat description '$rule', ignored\n";
  } else {
    $hat = $rules[1];
    $output_rules{$hat} = ( );
  }
}

my $bin = shift @ARGV;
!(-e $bin || $nowarn) && print STDERR "Warning: execname '$bin': no such file or directory\n";

for my $rule (@ARGV) {
  #($fn, @rules) = split (/:/, $rule);
  if ($rule =~ /^(tcp|udp)/) {
    # netdomain rules
    emit_netdomain($rule);
  } elsif ($rule =~ /^cap:/) {
    emit_cap($rule);
  } elsif ($rule =~ /^flag:/) {
    emit_flag($rule);
  } elsif ($rule =~ /^hat:/) {
    emit_hat($rule);
  } else {
    emit_file($rule);
  }
}

sub dump_flags {
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
dump_flags('__no_hat');
print STDOUT "{\n";
foreach my $outrule (@{$output_rules{'__no_hat'}}) {
  print STDOUT $outrule;
}
foreach my $hat (keys %output_rules) {
  if (not $hat =~ /^__no_hat$/) {
    print STDOUT "\n  ^$hat";
    dump_flags($hat);
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
