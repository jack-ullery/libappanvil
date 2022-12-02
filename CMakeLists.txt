cmake_minimum_required (VERSION 3.16.3)

project (aa-parse C CXX)

#### Set some variables #####
set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/parser)
set(AUTOGEN_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

set(LIBRARY_NAME ${PROJECT_NAME}-dev)

# Create the directory, so that it exists for FLEX/BISON to use 
file(MAKE_DIRECTORY ${AUTOGEN_SOURCE_DIR})

### Sources that need to be built ###
set(SOURCES
  ${PROJECT_SOURCE_DIR}/lib.c
  ${PROJECT_SOURCE_DIR}/parser.cc
  ${PROJECT_SOURCE_DIR}/parser_include.c
  ${PROJECT_SOURCE_DIR}/tree/TreeNode.cc
  ${PROJECT_SOURCE_DIR}/tree/ParseTree.cc
)

set(MAIN_SOURCE
  ${PROJECT_SOURCE_DIR}/parser_main.cc
)

set(PARSE_INPUT ${PROJECT_SOURCE_DIR}/parser_yacc.y)
set(LEXER_INPUT ${PROJECT_SOURCE_DIR}/parser_lex.l)

#### Bison stuff ####
find_package(BISON REQUIRED)

BISON_TARGET(PARSER 
              ${PARSE_INPUT} 
              ${AUTOGEN_SOURCE_DIR}/parser_yacc.cc
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_yacc.h)

#### Flex stuff ####
find_package(FLEX 2.5.5 REQUIRED)

FLEX_TARGET(LEXER 
              ${LEXER_INPUT} 
              ${AUTOGEN_SOURCE_DIR}/parser_lex.cc
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_lex.h)

ADD_FLEX_BISON_DEPENDENCY(LEXER PARSER)

#### Set Compiler Options ####
set(CMAKE_CXX_FLAGS "-g -Wall -Wextra")
set(CMAKE_CXX_STANDARD 14)

## set_source_files_properties(${CXX_SOURCES} PROPERTIES LANGUAGE CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#### Create the library ####
add_library(${LIBRARY_NAME} ${SOURCES} ${FLEX_LEXER_OUTPUTS} ${BISON_PARSER_OUTPUT_SOURCE})

target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(${LIBRARY_NAME} PUBLIC ${AUTOGEN_SOURCE_DIR})

#### Create the final executable ####
add_executable(${PROJECT_NAME} ${MAIN_SOURCE})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})

#### Add tests ####
enable_testing()
set(PROFILE_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/test/simple_tests)

file(GLOB_RECURSE 
     TEST_PROFILES 
     ${PROFILE_SOURCE_DIR}/*/*.sd
)

# Add each example profile as a test case
foreach(PROFILE ${TEST_PROFILES})
  # Determine whether the profile should pass or fail
  file(READ ${PROFILE} PROFILE_TEXT)
  string(FIND "${PROFILE_TEXT}" "EXRESULT PASS" TEST_SHOULD_PASS)

  # Strip the filename from the path
  file(RELATIVE_PATH PROFILE_NAME ${PROFILE_SOURCE_DIR} ${PROFILE})

  # Create the test
  add_test(${PROFILE_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME} ${PROFILE})

  # If the test should fail, set "WILL_FAIL" property
  if(NOT ${TEST_SHOULD_PASS} EQUAL -1)
      set_tests_properties(${PROFILE_NAME} PROPERTIES WILL_FAIL FALSE)
  else()
      set_tests_properties(${PROFILE_NAME} PROPERTIES WILL_FAIL TRUE)
  endif()
endforeach()