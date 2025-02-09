# libappanvil
A community-built C++ library to parse, read, and modify AppArmor profiles.

This library is used by the [AppAnvil](https://github.com/jack-ullery/AppAnvil) project.

## Dependencies
### Compile Time
Packages needed to compile the library:
* CMake
* PkgConfig
* clang (or an equivalent C++ compiler)
* Bison
* Flex

#### Install commands (Ubuntu)
```
sudo apt install pkg-config cmake clang bison flex libfl-dev
```

#### Install commands (openSUSE)
```
sudo zypper in cmake clang bison flex
```

### Testing (Optional)
Additional packages needed to run the tests:
* GoogleTest
* GoogleMock

#### Install commands (Ubuntu)
```
sudo apt install libgtest-dev libgmock-dev
```

#### Install commands (openSUSE)
```
sudo zypper in gtest gmock
```

### Linters and Static Analysis (Optional)
Optional packages needed to run linters and static analysis checks:
* clang-tidy
* cppcheck

#### Install commands (Ubuntu)
```
sudo apt install clang-tidy-15 cppcheck
```

#### Install commands (openSUSE)
```
sudo apt install clang cppcheck
```

## Compilation Instructions
### Prebuild
If you want to run the tests, first you must load the example profiles from the main [apparmor](https://gitlab.com/apparmor/apparmor/-/tree/master/parser/tst/simple_tests) repository. These profiles are included in a submodule for convenience.
```
git submodule update --init --recursive --remote
```

Before you build the library, you should first generate the makefile by running:
```
cmake .
```

Optionally, if you want to run linters and static analysis checks:
```
cmake -DANALYZE=TRUE .
```

### Build
After the makefile is generated, you can build the library:
```
make
```

Alternatively, you can build and install the library, to make it useable by other programs:
```
sudo make install
```

### Test
To build an run the tests:
```
make libappanvil_test -j$(nproc)
make test
```

To only run certain tests (using regex):
```
ctest -R e2e
```

## Uninstall Instructions
If you installed the library using `sudo make install`, then you can also uninstall it by running:
```
sudo make uninstall
```
