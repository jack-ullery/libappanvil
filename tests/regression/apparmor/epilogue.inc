if [ -n "$do_onexit" ] 
then
	$do_onexit
fi

if [ -n "$subdomain" -a -f "$profile" -a ${profileloaded:-0} -eq 1 ]
then
	removeprofile
fi

if [ "$retaintmpdir" = "true" ]
then
	echo "Files retained in: $tmpdir"
else
	rm -rf $tmpdir
fi

# Remove temporary users that were created
for testuser in $testusers; do
    deluser $testuser >/dev/null
done

if [ -n "$_fatal" ] ; then
	exit 127
else
	exit $num_testfailures
fi
