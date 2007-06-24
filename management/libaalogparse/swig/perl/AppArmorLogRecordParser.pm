# This file was created automatically by SWIG 1.3.29.
# Don't modify this file, modify the SWIG interface instead.
package AppArmorLogRecordParser;
require Exporter;
require DynaLoader;
@ISA = qw(Exporter DynaLoader);
package AppArmorLogRecordParserc;
bootstrap AppArmorLogRecordParser;
package AppArmorLogRecordParser;
@EXPORT = qw( );

# ---------- BASE METHODS -------------

package AppArmorLogRecordParser;

sub TIEHASH {
    my ($classname,$obj) = @_;
    return bless $obj, $classname;
}

sub CLEAR { }

sub FIRSTKEY { }

sub NEXTKEY { }

sub FETCH {
    my ($self,$field) = @_;
    my $member_func = "swig_${field}_get";
    $self->$member_func();
}

sub STORE {
    my ($self,$field,$newval) = @_;
    my $member_func = "swig_${field}_set";
    $self->$member_func($newval);
}

sub this {
    my $ptr = shift;
    return tied(%$ptr);
}


# ------- FUNCTION WRAPPERS --------

package AppArmorLogRecordParser;

*parse_record = *AppArmorLogRecordParserc::parse_record;
*free_record = *AppArmorLogRecordParserc::free_record;

############# Class : AppArmorLogRecordParser::aa_log_record ##############

package AppArmorLogRecordParser::aa_log_record;
use vars qw(@ISA %OWNER %ITERATORS %BLESSEDMEMBERS);
@ISA = qw( AppArmorLogRecordParser );
%OWNER = ();
%ITERATORS = ();
*swig_version_get = *AppArmorLogRecordParserc::aa_log_record_version_get;
*swig_version_set = *AppArmorLogRecordParserc::aa_log_record_version_set;
*swig_event_get = *AppArmorLogRecordParserc::aa_log_record_event_get;
*swig_event_set = *AppArmorLogRecordParserc::aa_log_record_event_set;
*swig_pid_get = *AppArmorLogRecordParserc::aa_log_record_pid_get;
*swig_pid_set = *AppArmorLogRecordParserc::aa_log_record_pid_set;
*swig_task_get = *AppArmorLogRecordParserc::aa_log_record_task_get;
*swig_task_set = *AppArmorLogRecordParserc::aa_log_record_task_set;
*swig_bitmask_get = *AppArmorLogRecordParserc::aa_log_record_bitmask_get;
*swig_bitmask_set = *AppArmorLogRecordParserc::aa_log_record_bitmask_set;
*swig_operation_get = *AppArmorLogRecordParserc::aa_log_record_operation_get;
*swig_operation_set = *AppArmorLogRecordParserc::aa_log_record_operation_set;
*swig_denied_mask_get = *AppArmorLogRecordParserc::aa_log_record_denied_mask_get;
*swig_denied_mask_set = *AppArmorLogRecordParserc::aa_log_record_denied_mask_set;
*swig_requested_mask_get = *AppArmorLogRecordParserc::aa_log_record_requested_mask_get;
*swig_requested_mask_set = *AppArmorLogRecordParserc::aa_log_record_requested_mask_set;
*swig_profile_get = *AppArmorLogRecordParserc::aa_log_record_profile_get;
*swig_profile_set = *AppArmorLogRecordParserc::aa_log_record_profile_set;
*swig_name_get = *AppArmorLogRecordParserc::aa_log_record_name_get;
*swig_name_set = *AppArmorLogRecordParserc::aa_log_record_name_set;
*swig_name2_get = *AppArmorLogRecordParserc::aa_log_record_name2_get;
*swig_name2_set = *AppArmorLogRecordParserc::aa_log_record_name2_set;
*swig_attribute_get = *AppArmorLogRecordParserc::aa_log_record_attribute_get;
*swig_attribute_set = *AppArmorLogRecordParserc::aa_log_record_attribute_set;
*swig_parent_get = *AppArmorLogRecordParserc::aa_log_record_parent_get;
*swig_parent_set = *AppArmorLogRecordParserc::aa_log_record_parent_set;
*swig_magic_token_get = *AppArmorLogRecordParserc::aa_log_record_magic_token_get;
*swig_magic_token_set = *AppArmorLogRecordParserc::aa_log_record_magic_token_set;
*swig_info_get = *AppArmorLogRecordParserc::aa_log_record_info_get;
*swig_info_set = *AppArmorLogRecordParserc::aa_log_record_info_set;
*swig_active_hat_get = *AppArmorLogRecordParserc::aa_log_record_active_hat_get;
*swig_active_hat_set = *AppArmorLogRecordParserc::aa_log_record_active_hat_set;
sub new {
    my $pkg = shift;
    my $self = AppArmorLogRecordParserc::new_aa_log_record(@_);
    bless $self, $pkg if defined($self);
}

sub DESTROY {
    return unless $_[0]->isa('HASH');
    my $self = tied(%{$_[0]});
    return unless defined $self;
    delete $ITERATORS{$self};
    if (exists $OWNER{$self}) {
        AppArmorLogRecordParserc::delete_aa_log_record($self);
        delete $OWNER{$self};
    }
}

sub DISOWN {
    my $self = shift;
    my $ptr = tied(%$self);
    delete $OWNER{$ptr};
}

sub ACQUIRE {
    my $self = shift;
    my $ptr = tied(%$self);
    $OWNER{$ptr} = 1;
}


# ------- VARIABLE STUBS --------

package AppArmorLogRecordParser;

*AA_RECORD_EXEC_MMAP = *AppArmorLogRecordParserc::AA_RECORD_EXEC_MMAP;
*AA_RECORD_READ = *AppArmorLogRecordParserc::AA_RECORD_READ;
*AA_RECORD_WRITE = *AppArmorLogRecordParserc::AA_RECORD_WRITE;
*AA_RECORD_EXEC = *AppArmorLogRecordParserc::AA_RECORD_EXEC;
*AA_RECORD_LINK = *AppArmorLogRecordParserc::AA_RECORD_LINK;
*AA_RECORD_SYNTAX_V1 = *AppArmorLogRecordParserc::AA_RECORD_SYNTAX_V1;
*AA_RECORD_SYNTAX_V2 = *AppArmorLogRecordParserc::AA_RECORD_SYNTAX_V2;
*AA_RECORD_SYNTAX_UNKNOWN = *AppArmorLogRecordParserc::AA_RECORD_SYNTAX_UNKNOWN;
*AA_RECORD_INVALID = *AppArmorLogRecordParserc::AA_RECORD_INVALID;
*AA_RECORD_ERROR = *AppArmorLogRecordParserc::AA_RECORD_ERROR;
*AA_RECORD_AUDIT = *AppArmorLogRecordParserc::AA_RECORD_AUDIT;
*AA_RECORD_ALLOWED = *AppArmorLogRecordParserc::AA_RECORD_ALLOWED;
*AA_RECORD_DENIED = *AppArmorLogRecordParserc::AA_RECORD_DENIED;
*AA_RECORD_HINT = *AppArmorLogRecordParserc::AA_RECORD_HINT;
*AA_RECORD_STATUS = *AppArmorLogRecordParserc::AA_RECORD_STATUS;
1;
