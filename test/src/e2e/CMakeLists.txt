cmake_minimum_required (VERSION 3.16.3)

project(end-to-end-test C CXX)

set(TEST_SOURCES
  ./main.cc
  ./abstractions.cc
)

#### Check that gtest is installed ####
find_package(PkgConfig)
pkg_check_modules(GTEST gtest)

#### If gtest is installed, create the test executable ####
if(${GTEST_FOUND})
  add_executable(${PROJECT_NAME} ${TEST_SOURCES})

  target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})
  target_link_libraries(${PROJECT_NAME} PUBLIC gtest)

  #Set the location of profiles as a global variable for the tests
  target_compile_definitions(${PROJECT_NAME} PUBLIC -DPROFILE_SOURCE_DIR="${PROFILE_SOURCE_DIR}")
endif()