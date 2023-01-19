cmake_minimum_required (VERSION 3.16.3)

project (apparmor-parser C CXX)

#### Set some variables #####
set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/src)
set(AUTOGEN_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

set(LIBRARY_NAME ${PROJECT_NAME}-dev)

# Create the directory, so that it exists for FLEX/BISON to use 
file(MAKE_DIRECTORY ${AUTOGEN_SOURCE_DIR})

### Sources that need to be built ###
set(SOURCES
  ${PROJECT_SOURCE_DIR}/parser/tree/TreeNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/ParseTree.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/ProfileNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/PrefixNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/AliasNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/RuleNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/FileNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/LinkNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/AbstractionNode.cc
  ${PROJECT_SOURCE_DIR}/parser/tree/RuleList.cc
  ${PROJECT_SOURCE_DIR}/parser/lib.c
  ${PROJECT_SOURCE_DIR}/parser/parser.cc
  ${PROJECT_SOURCE_DIR}/apparmor_file_rule.cc
  ${PROJECT_SOURCE_DIR}/apparmor_profile.cc
  ${PROJECT_SOURCE_DIR}/apparmor_parser.cc
)

set(PARSE_INPUT ${PROJECT_SOURCE_DIR}/parser/parser_yacc.y)
set(LEXER_INPUT ${PROJECT_SOURCE_DIR}/parser/parser_lex.l)

# Public headers that will be used by the client
set(OUTPUT_HEADERS
  ${PROJECT_SOURCE_DIR}/apparmor_file_rule.hh
  ${PROJECT_SOURCE_DIR}/apparmor_profile.hh
  ${PROJECT_SOURCE_DIR}/apparmor_parser.hh
)

#### Bison stuff ####
find_package(BISON REQUIRED)

BISON_TARGET(PARSER 
              ${PARSE_INPUT} 
              ${AUTOGEN_SOURCE_DIR}/parser_yacc.cc
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_yacc.hh)

#### Flex stuff ####
find_package(FLEX 2.5.5 REQUIRED)

FLEX_TARGET(LEXER 
              ${LEXER_INPUT} 
              ${AUTOGEN_SOURCE_DIR}/parser_lex.cc
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_lex.hh)

ADD_FLEX_BISON_DEPENDENCY(LEXER PARSER)

#### Set Compiler Options ####
set(CMAKE_CXX_FLAGS "-g -Wall -Wextra")
set(CMAKE_CXX_STANDARD 17)

## set_source_files_properties(${CXX_SOURCES} PROPERTIES LANGUAGE CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#### Create the library ####
add_library(${LIBRARY_NAME} ${SOURCES} ${FLEX_LEXER_OUTPUTS} ${BISON_PARSER_OUTPUT_SOURCE})

target_include_directories(${LIBRARY_NAME} PUBLIC  ${PROJECT_SOURCE_DIR})
target_include_directories(${LIBRARY_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/parser)
target_include_directories(${LIBRARY_NAME} PRIVATE ${AUTOGEN_SOURCE_DIR})

# Create target to install library
install(TARGETS ${LIBRARY_NAME} DESTINATION lib)
install(FILES ${OUTPUT_HEADERS} DESTINATION include)

# Create uninstall target
# Copied from: https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#can-i-do-make-uninstall-with-cmake
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

#### Create the test executable ####
enable_testing()
add_subdirectory(test)
