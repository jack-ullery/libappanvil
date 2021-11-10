if HAVE_PYTHON

# NOTE: tests needs to exist in test/test*.py for python's setuptools
# not to treat it as a script to install.

test_python.py: test_python.py.in $(top_builddir)/config.status
	$(AM_V_GEN)cd "$(top_builddir)" && \
	$(SHELL) ./config.status --file="swig/python/test/$@"
	chmod +x test_python.py

CLEANFILES = test_python.py

# bah, how brittle is this?
PYTHON_DIST_BUILD_PATH = '$(builddir)/../build/$$($(PYTHON) -c "import sysconfig; print(\"lib.%s-%s\" %(sysconfig.get_platform(), sysconfig.get_python_version()))")'

TESTS	= test_python.py
TESTS_ENVIRONMENT = \
  LD_LIBRARY_PATH='$(top_builddir)/src/.libs:$(PYTHON_DIST_BUILD_PATH)' \
  PYTHONPATH='$(PYTHON_DIST_BUILD_PATH)'

endif
