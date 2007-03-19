#!/bin/bash

# a brain dead script to provide kernel patches from the apparmor svn module
# for snapshot releases

# gen-k-patches.sh linux-2.6.16.43 ~/immunix/forge-svn/trunk/module/apparmor/ ~/immunix/forge-svn/trunk/kernel-patches/2.6.16 ~/linux-kernels/

usage()
{
    echo "Usage: $0 kernelsource module patches destination"
    exit 0
}

# $1 - module dir
get_repo_version()
{
    local origWD=`pwd`
    cd "$1"
    if [ -x /usr/bin/svn ] ; then
	REPO_VERSION=`/usr/bin/svn info . 2> /dev/null | grep "^Last Changed Rev:" | sed "s/^Last Changed Rev: //"`
    fi
    if [ -z ${REPO_VERSION} ] ; then
	REPO_VERSION="unknown"
    fi
    cd "${origWD}"
    echo "Done Getting Repo version ${REPO_VERSION}"
}

cleanup()
{
# ????
echo "cleanup"
}


add_files()
{
    local f
    for f in $1/* ; do
	if [ -d "$f" ] ; then
	    add_files "$f" "$2"
	else
	    quilt add security/apparmor/${f#$2}
	fi
    done
}

# $1 - kernel dir
# $2 - dir with patches
# $3 - module
# $4 - kernel ver #
# $5 - svn ver #
# $6 - destination
patches_for_kernel()
{
    local WD=`pwd`
    if [ -d $2/patches ] ; then
	cp -r $2/patches $6/
	cp -r $2/../README.snapshot $6/
	cp -r $2/patches $1

    else
	mkdir $6/patches
    fi

    cd $1
    quilt push -a

    quilt new apparmor.diff
    add_files $3 $3
    cp -r $3 security/apparmor
    quilt refresh
    if [ -d $2/postapply/module ] ; then
	mv patches/series patches/series.bak
	cp -r $2/postapply/module/* patches/
	cp patches/series.bak patches/series
	cat $2/postapply/module/series >>patches/series
	quilt push -a
    fi

    echo "creating patches in $6"
    quilt diff -p ab --combine apparmor.diff >foo
    echo "AppArmor kernel patches for repo version $5" >$6/patches/apparmor-$4-v$5.diff
    diffstat foo >>$6/patches/apparmor-$4-v$5.diff
    cat foo >>$6/patches/apparmor-$4-v$5.diff
    cat patches/series.bak | sed "s/apparmor.diff/apparmor-$4-v$5.diff/" > $6/patches/series

    quilt diff -p ab --combine - >foo
    echo "AppArmor kernel patches for repo version $5" >$6/apparmor-$4-v$5-fullseries.diff
    diffstat foo >>$6/apparmor-$4-v$5-fullseries.diff
    cat foo >>$6/apparmor-$4-v$5-fullseries.diff

    quilt pop -a
    rm -rf foo
    rm -rf security/apparmor
    rm -rf patches
    rm -rf .pc
    cd $WD
}

VERSION=`expr "$1" : '.*\(2\.6\.[^ /\t]*\)' `
if [ -z ${VERSION} ]; then
    echo "script expects a kernelsource dir with embedded version tag."
    echo " eg. linux-2.6.16rc1"
    exit 1;
fi


if ! [ -e "$4/$VERSION" ] ; then
    echo "Making destination $4/$VERSION"
    mkdir "$4/$VERSION"
else
    echo "Destination $4/$VERSION already exists"
fi

get_repo_version $2

patches_for_kernel $1 $3 $2 $VERSION $REPO_VERSION "$4/$VERSION"

WD=`pwd`
cd $4
tar --exclude=.svn -cf "apparmor-kernel-patches-$VERSION.tar" "$VERSION"
gzip "apparmor-kernel-patches-$VERSION.tar"
cd $WD
