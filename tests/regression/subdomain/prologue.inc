# vim:syntax=sh
#
# prologue.inc
#
# Test infrastructure support.
#
# This file should be included by each test case
# It does a lot of hidden 'magic',  Downside is that
# this magic makes debugging fauling tests more difficult.
# Running the test with the '-r' option can help.
#
# Userchangeable variables (tmpdir etc) should be specified in
# uservars.inc
# 
# Cleanup is automatically performed by epilogue.inc
#
# For this file, functions are first, entry point code is at end, see "MAIN"

fatalerror()
{
	# global _fatal
	if [ -z "$_fatal" ]
	then
		_fatal=true	# avoid cascading fatal errors
		echo "Fatal Error ($testname): $*" >&2
		exit 127
	fi
}

testerror()
{
	fatalerror "Unable to run test sub-executable"
}

testfailed()
{
	# global num_testfailures teststatus
	num_testfailures=$(($num_testfailures + 1))
	teststatus="fail"
}

error_handler()
{
	#invoke exit_handler to cleanup
	exit_handler

	fatalerror "Unexpected shell error. Run with -x to debug"
}

# invoked whenever we exit (normally, interrupt 
# or exit due to testfailure()/error_handler()
exit_handler()
{
	# global bin
	if [ -d "$bin" ]
	then
		. $bin/epilogue.inc
	fi
}

genrunscript()
{
	# create a log so we can run test again if -retain specified

	local runfile
	#global tmpdir profile outfile
	
	if [ "$retaintmpdir" = "true" ]
	then
		runfile=$tmpdir/runtest
		echo "$subdomain ${parser_args} < $profile" > $runfile
		echo -n "$testexec " >> $runfile
		while [ $# -gt 0 ] ; do
		      echo -n "\"$1\" " >> $runfile
		      shift
		done
		echo "2>&1 > $outfile" >> $runfile
		echo "echo $testname: \`cat $outfile\`" >> $runfile
		echo "$subdomain ${parser_args} -R < $profile" >> $runfile
	fi
}

resolve_symlink()
{
	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	local link linkdir targetdir targetname

	link=$1

	while [ -h ${link} ]
	do
		if [ -x /usr/bin/readlink ] ; then 
			target=$(/usr/bin/readlink ${link})
		else 
			# I'm sure there's a more perlish way to do this
			target=$( perl -e "printf (\"%s\n\", readlink(\"${link}\"));") 
			#target=$( perl -e "if (\$foo = readlink(\"${link}\")){ \
			#			printf (\"%s\n\", \$foo) \
			#		    } else { \
			#		    	print \"${link}\n\"; \
			#		    };")
		fi
		case "${target}" in
			/*)  link=${target}
 			     ;;
			*) linkdir=$(dirname ${link})
			   targetdir=$(dirname ${target})
			   targetname=$(basename ${target})
			   linkdir=$(cd ${linkdir}/${targetdir} ; pwd)
			   link=${linkdir}/${targetname}
			   ;;
		esac
				
	done

	if [ -e ${link} ]
	then
		echo ${link}
		return 0
	else
		return 1
	fi
}

resolve_libs()
{
	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	local exec mode libpath libs
	# global dynlibs

	exec=$1

	if [ ! -x $1 ]
	then
		fatalerror "invalid test executable $test"
	fi

	# Suck. SuSE's ldd has a line "linux-gate.so.1 =>  (0xffffe000)"
	#       Red Hat's ldd has "/lib/ld-linux.so.2 (0x007b1000)"
	# good ${DIETY}, what gross kludgage.
	libs=$(ldd $exec | egrep -v "linux-(vdso(32|64)|gate).so.1" | sed 's~^.*=> \(/.*\) (.*$~\1~' | awk '{print $1}')

	dynlibs="/etc/ld.so.cache:r"

	# bleah, this is cheeseball. on systems with a stackguard
	# compiler, we also need access to /dev/urandom
	for i in $libs /dev/urandom
	do
		mode=rm
		# resolve possible symlinks before checking for ld pattern
		# this is necessary because some architectures (zSeries)
		# use nonconforming ld symlink names, like ld64.so
		libpath=`resolve_symlink $i`		
		case $libpath in
		/lib/ld[.-]*) mode=${mode}px
			   ;;
		/lib64/ld[.-]*) mode=${mode}px
			   ;;
		*) mode=${mode}ix
			   ;;
		esac
		dynlibs="$dynlibs ${libpath}:${mode}"
	done
}

runtestbg()
{
	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	# global _testdesc _pfmode _known _pid outfile
	
	_testdesc=$1
	if [ ${2:0:6} == "known_" ] ; then
		_pfmode=${2#known_}
		_known=" (known problem)"
        else
		_pfmode=$2
		_known=""
        fi

	shift 2
	
	genrunscript "$@"
	
	$testexec "$@" > $outfile 2>&1 &
	
	_pid=$!
}

checktestbg()
{
	# global _pid _rc outfile 
	local rc

	wait $_pid
	rc=$?
	if [ $rc -gt 128 ]
	then
		echo "SIGNAL$(($rc - 128))" > $outfile
	fi
	checktestfg
}

runtestfg()
{
	# global _testdesc _pfmode _known outfile
	_testdesc=$1
	if [ ${2:0:6} == "known_" ] ; then
		_pfmode=${2#known_}
		_known=" (known problem)"
        else
		_pfmode=$2
		_known=""
        fi
	shift 2
	
	genrunscript "$@"
	
	$testexec "$@" > $outfile 2>&1
	test_rc=$?
	if [ $test_rc -gt 128 ]
	then
		echo "SIGNAL$(($test_rc - 128))" > $outfile
	fi
}

checktestfg()
{
	# global _pfmode _known _testdesc outfile teststatus testname
	local ret expectedsig killedsig

	ret=`cat $outfile 2>/dev/null`
	teststatus=pass
	
	case "$ret" in
		PASS)	if [ "$_pfmode" != "pass" ]
			then
				echo "Error: ${testname} passed. Test '${_testdesc}' was expected to '${_pfmode}'${_known}"
				testfailed
			fi
			;;
		FAIL*)  if [ "$_pfmode" != "fail" ]
			then
				echo "Error: ${testname} failed. Test '${_testdesc}' was expected to '${_pfmode}'${_known}. Reason for failure '${ret}'"
				testfailed
			fi
			;;
		SIGNAL*) killedsig=`echo $ret | sed 's/SIGNAL//'`
			case "$_pfmode" in
			signal*) expectedsig=`echo ${_pfmode} | sed 's/signal//'`
				if [ -n "${expectedsig}" -a ${expectedsig} != ${killedsig} ]
				then
					echo "Error: ${testname} failed. Test '${_testdesc}' was expected to terminate with signal ${expectedsig}${_known}. Instead it terminated with signal ${killedsig}"
					testfailed
				fi
				;;
			*) 	echo "Error: ${testname} failed. Test '${_testdesc}' was expected to '${_pfmode}'${_known}. Reason for failure 'killed by signal ${killedsig}'"
				testfailed
				;;	
			esac
			;;
		*)	testerror
			;;
	esac
}

runchecktest()
{
	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	runtestfg "$@"
	checktestfg
}

runchecktest_errno()
{
	local errno=$(perl -MPOSIX -e 'printf "%d\n", '$1';')
	shift 1

	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	runtestfg "$@"
	if [ "$test_rc" == "$errno" ] ; then
		checktestfg
	else
		echo "Error: ${testname} failed. Test '${_testdesc}' was expected to '${_pfmode}'${_known}. Reason for failure expect errno ${errno} != ${test_rc}"
		testfailed
	fi
}

emit_profile()
{
	if [ -z "${__NO_TRAP_ERR}" ]	
	then
		trap "error_handler" ERR
	fi

	local subprofile wflag
	#global name outfile profile dynlibs profilenames

	subprofile=0
	wflag=""

	case "$1" in 
		*^*) wflag="--nowarn"
		     subprofile=1
		     ;;
	esac

	mkflags="${wflag} ${escapeflag}"

	name=$1; perm=$2; shift 2

	if [ "$subprofile" -eq 1 -o "$nodefaults" -eq 1 ]
	then
		# skip dynamic libs for subprofiles
		$bin/mkprofile.pl ${mkflags} $name ${outfile}:w "$@" >> $profile
	else
		$bin/mkprofile.pl ${mkflags} $name ${name}:${perm} $dynlibs ${outfile}:w "$@" >> $profile
	fi

	echo $name >> $profilenames
}
		
genprofile()
{
if [ -z "${__NO_TRAP_ERR}" ]
then
	trap "error_handler" ERR
fi
	
	local num_emitted imagename hat args arg names1 names2
	#global complainflag escapeflag nodefaults profile profilenames
	local hat_string="hat:"

	complainflag=""
	escapeflag=""
	nodefaults=0
	while /bin/true 
	do
		case "$1" in 
			"-C") complainflag="-C"
			      ;;
			"-E") escapeflag="-E"
			      ;;
			"-N") nodefaults=1
			      ;;
			*) break
			   ;;
		esac
		shift
	done

	# save previous profile
	if [ -f $profile ] 
	then
		mv $profile ${profile}.old
		mv $profilenames ${profilenames}.old
	fi

	num_emitted=0

	while /bin/true
	do
		imagename=$test
		imageperm=rix

		# image/subhat allows overriding of the default
		# imagename which is based on the testname
		#
		# it is most often used after --, in fact it is basically
		# mandatory after --
		case "$1" in
			image=*) imagename=`echo $1 | sed 's/^image=[rix]*//'`
				 if [ ! -x "$imagename" ]
				 then
					fatalerror "invalid imagename specified in input '$1'"
				 fi
				 perm=`echo $1 | sed -n 's/^image=\([rix]*\).*$/\1/p'`
				 if [ -n "$perm" ]
				 then
					imageperm=$perm
				 fi
				 num_emitted=0
				 shift
				 ;;
			subhat=*) fatalerror "'subhat=hatname' is no longer supported ('$1')"
				 shift
				 ;;
		esac

		#give every profile/hat access to change_hat
		args[0]="/proc/*/attr/current:w"
		num_args=1
		while [ $# -gt 0 ]
		do
			arg="$1"
			shift

			# -- is the seperator between profiles
			if [ "$arg" == "--" ]
			then
				eval emit_profile \"$imagename\" \"$imageperm\" \
					$(for i in $(seq 0 $((${num_args} - 1))) ; do echo \"\${args[${i}]}\" ; done)
				num_emitted=$((num_emitted + 1))
				#give every profile/hat access to change_hat
				args[0]="/proc/*/attr/current:w"
				num_args=1
				continue 2
			elif [ ${arg:0:4} == "hat:" ] ; then
				args[${num_args}]=${arg}
				num_args=$(($num_args + 1))
				args[${num_args}]="/proc/*/attr/current:w"
				num_args=$(($num_args + 1))
			else
				args[${num_args}]=${arg}
				num_args=$(($num_args + 1))
			fi
		done

		# output what is in args, or force empty profile
		if [ -n "$args" -o $num_emitted -eq 0 ] ; then
			eval emit_profile \"$imagename\" \"$imageperm\" \
				$(for i in $(seq 0 $((${num_args} - 1))) ; do echo \"\${args[${i}]}\" ; done)
		fi

		break
	done

	# if old and new profiles consist of the same entries
	# we can do a replace, else remove/reload
	if [ $profileloaded -eq 1 ]
	then
		names1=$tmpdir/sorted1
		names2=$tmpdir/sorted2
		sort $profilenames > $names1
		sort ${profilenames}.old > $names2

		if cmp -s $names1 $names2
		then
			replaceprofile
		else	
			removeprofile ${profile}.old
			loadprofile
		fi

		rm -f $names1 $names2
	
	else
		loadprofile
	fi

	rm -f ${profile}.old ${profilenames}.old
}

loadprofile()
{
	#global complainflaf profile profileloaded

	$subdomain ${parser_args} $complainflag < $profile > /dev/null
	if [ $? -ne 0 ]
	then
		removeprofile
		fatalerror "Unable to load profile $profile"
	else
		profileloaded=1
	fi
}

replaceprofile()
{
	#global complainflag profile

	$subdomain ${parser_args} -r $complainflag < $profile > /dev/null
	if [ $? -ne 0 ]
	then
		fatalerror "Unable to replace profile $profile"
	fi
}

removeprofile()
{
	local remprofile
	#global profile profileloaded

	if [ -f "$1" ]
	then
		remprofile=$1
	else
		remprofile=$profile
	fi

	$subdomain ${parser_args} -R < $remprofile > /dev/null
	if [ $? -ne 0 ]
	then
		fatalerror "Unable to remove profile $remprofile"
	else
		profileloaded=0
	fi
}

settest()
{
	if [ -z "${__NO_TRAP_ERR}" ]
	then
		trap "error_handler" ERR
	fi

	#global test testname testexec outfile profileloaded

	#testname is the basename of the test, i,e 'open'
	#test is the full path to the test executable.
	#testexec is the path than will be run, normally this is the same
	#  as $test, but occasionally, you may want to invoke a wrapper which
	#  will run the test. In this case 'settest <testname> "wrapper {}'
	#  will result in testexec invoking wrapper. {} will be replaced with 
	#  $test 

	testname=$1

	if [ $# -eq 1 ]
	then
		test=$bin/$1
		testexec=$test
	elif [ $# -eq 2 ]
	then
		test=$bin/$1
		testexec=`echo $2 | sed "s~{}~$test~"`
	else
		fatalerror "settest, illegal usage"
	fi

	outfile=$tmpdir/output.$1

	if [ -x $test ]
	then
		# build list of dynamic libraries required by this executable
		resolve_libs $test
	fi

	# Remove any current profile if loaded
	if [ $profileloaded -eq 1 ]
	then
		removeprofile
	fi
}

# ----------------------------------------------------------------------------

# MAIN

trap "exit_handler" EXIT
trap "error_handler" ERR 2> /dev/null
if [ $? -ne 0 ]
then
	__NO_TRAP_ERR="true"
fi


if [ `whoami` != "root" ]
then
	fatalerror "Must be root to run $0"
fi

if [ ! -d "$bin" ]
then
	fatalerror "$0 requires \$bin pointing to binary directory"
fi

# parse arguments. 
# -r/-retain: flag to retain last failing testcase in tmpdir
if [ "$1" == "-retain" -o "$1" == "-r" ]
then
	retaintmpdir=true
else
	retaintmpdir=false
fi

# load user changeable variables
. $bin/uservars.inc

if [ ! -x $subdomain ]
then
	fatalerror "AppArmor parser '$subdomain' is not executable"
fi

profileloaded=0

tmpdir=$(mktemp -d $tmpdir-XXXXXX)
chmod 755 ${tmpdir}
export tmpdir

#set initial testname based on name of script
settest `basename $0 .sh`

profile=$tmpdir/profile
profilenames=$tmpdir/profile.names
num_testfailures=0	# exit code of script is set to #failures
