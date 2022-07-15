# Test data generated elsewhere

The tests in `parser` generate additional test profiles in
`parser/tst/simple_tests/`: see `gen-dbus.py` and `gen-xtrans.py`.

`utils/test/test-parser-simple-tests.py` uses this test data when it is
available. If this test data has not been generated, this test will not
complain: it will simply exercise fewer test profiles.

# Running individual tests

Python's unittest allows individual tests to be executed by specifying the class name and the test on the command line.
When running tests individually, the unittest framework executes the "setUp" and "tearDown" methods automatically.
For more information, refer to the [unittest documentation](https://docs.python.org/3/library/unittest.html).

Make sure to set the environment variables pointing to the in-tree apparmor modules, and the in-tree libapparmor and its python wrapper:

```bash
$ export PYTHONPATH=..:../../libraries/libapparmor/swig/python/build/$(/usr/bin/python3 ../../libraries/libapparmor/swig/python/test/buildpath.py)
$ export __AA_CONFDIR=.
```

To execute the test individually, run:

```bash
$ python3 ./test-tile.py ClassFoo.test_bar
```
