#!/usr/bin/python3
# the build path has changed in setuptools 62.1:
# https://github.com/pypa/setuptools/commit/1c23f5e1e4b18b50081cbabb2dea22bf345f5894
import sys
import sysconfig
import setuptools


if tuple(map(int, setuptools.__version__.split("."))) >= (62, 1):
    identifier = sys.implementation.cache_tag
else:
    identifier = "%d.%d" % sys.version_info[:2]
print("lib.%s-%s" % (sysconfig.get_platform(), identifier))
