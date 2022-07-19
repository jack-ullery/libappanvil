#!/usr/bin/python3
# the build path has changed in setuptools 61.2
import sys
import sysconfig
import setuptools
if tuple(map(int,setuptools.__version__.split("."))) >= (61, 2):
    identifier = sys.implementation.cache_tag
else:
    identifier = "%d.%d" % sys.version_info[:2]
print("lib.%s-%s" % (sysconfig.get_platform(), identifier))
