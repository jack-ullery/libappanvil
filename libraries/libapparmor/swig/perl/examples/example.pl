require LibAppArmor;

$msg = "type=APPARMOR msg=audit(1168662182.495:58): PERMITTING r access to /home/matt/projects/change_hat_test/test (test_hat(27871) profile /home/matt/projects/change_hat_test/test_hat active null-complain-profile)";

my($test) = LibAppArmorc::parse_record($msg);

if (LibAppArmor::aa_log_record::swig_event_get($test) == $AppArmorLogRecordParser::AA_RECORD_ALLOWED )
{
	print "AA_RECORD_ALLOWED\n";
}

print "Audit ID: " . LibAppArmor::aa_log_record::swig_audit_id_get($test) . "\n";
print "PID: " . LibAppArmor::aa_log_record::swig_pid_get($test) . "\n";

LibAppArmorc::free_record($test);
