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

exit $num_testfailures
