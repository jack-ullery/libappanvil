cmake_minimum_required (VERSION 3.16.3)

project(simple-test C CXX)

set(TEST_SOURCES ./main.cc)

#### Create the test executable ####
add_executable(${PROJECT_NAME} ${TEST_SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})

#### Create fixture for tests ####
add_test(test_build
  "${CMAKE_COMMAND}"
  --build "${CMAKE_BINARY_DIR}"
  --config "$<CONFIG>"
  --target "${PROJECT_NAME}"
)
set_tests_properties(test_build PROPERTIES FIXTURES_SETUP test_fixture)

# To allow whitespace in test names
cmake_policy(SET CMP0110 NEW)

#### Add the tests ####
foreach(PROFILE ${TEST_PROFILES})
  # Determine whether the profile should pass or fail
  file(READ ${PROFILE} PROFILE_TEXT)
  string(FIND "${PROFILE_TEXT}" "#=EXRESULT PASS" TEST_SHOULD_PASS)
  string(FIND "${PROFILE_TEXT}" "#=DISABLED"      TEST_DISABLED)

  # Strip the filename from the path
  file(RELATIVE_PATH PROFILE_NAME ${PROFILE_SOURCE_DIR} ${PROFILE})

  # Create the test, if it is not marked as disabled
  if(${TEST_DISABLED} EQUAL -1)
    set(TEST_NAME "[simple] ${PROFILE_NAME}")
    add_test(${TEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME} ${PROFILE})

    set_tests_properties(${TEST_NAME} PROPERTIES FIXTURES_REQUIRED test_fixture)

    # If the test should fail, set "WILL_FAIL" property
    if(NOT ${TEST_SHOULD_PASS} EQUAL -1)
        set_tests_properties(${TEST_NAME} PROPERTIES WILL_FAIL FALSE)
    else()
        set_tests_properties(${TEST_NAME} PROPERTIES WILL_FAIL TRUE)
    endif()
  endif()
endforeach()