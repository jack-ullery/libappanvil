cmake_minimum_required (VERSION 3.19)

project(end-to-end-test C CXX)

set(TEST_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/abstractions.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/file_rules.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/remove_function.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/add_function.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/edit_function.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/file_mode.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/parser.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tree/abstraction_rule_test.cc
)

#### Check that gtest is installed ####
find_package(PkgConfig)
pkg_check_modules(GTEST gtest)

include(GoogleTest)

# To allow whitespace in test names
cmake_policy(SET CMP0110 NEW)

#### If gtest is installed, create the test executable ####
if(${GTEST_FOUND})
  add_executable(${PROJECT_NAME} ${TEST_SOURCES})

  target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})
  target_link_libraries(${PROJECT_NAME} PUBLIC gtest)

  #### Create fixture for tests ####
  add_test(e2e_test_build
    "${CMAKE_COMMAND}"
    --build "${CMAKE_BINARY_DIR}"
    --config "$<CONFIG>"
    --target "${PROJECT_NAME}"
  )
  set_tests_properties(e2e_test_build PROPERTIES FIXTURES_SETUP e2e_test_fixture)

  # Set the location of profiles as a global variable for the tests
  target_compile_definitions(${PROJECT_NAME} PUBLIC -DPROFILE_SOURCE_DIR="${PROFILE_SOURCE_DIR}")
  target_compile_definitions(${PROJECT_NAME} PUBLIC -DADDITIONAL_PROFILE_SOURCE_DIR="${ADDITIONAL_PROFILE_SOURCE_DIR}")

  # Add the tests to ctest
  gtest_discover_tests(
    ${PROJECT_NAME}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
    TEST_PREFIX "[end-to-end] e2e."
    TEST_LIST ADDED_TESTS
  )

  set_tests_properties(${ADDED_TESTS} PROPERTIES FIXTURES_REQUIRED test_fixture)

endif()