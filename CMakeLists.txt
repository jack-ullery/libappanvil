cmake_minimum_required (VERSION 3.16.3)

project (aa-parse C CXX)

#### Set some variables #####
set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/parser)
set(AUTOGEN_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

# Create the directory, so that it exists for FLEX/BISON to use 
file(MAKE_DIRECTORY ${AUTOGEN_SOURCE_DIR})

### Sources that need to be built ###
set(SOURCES
  ${PROJECT_SOURCE_DIR}/af_rule.cc
  ${PROJECT_SOURCE_DIR}/af_unix.cc
  ${PROJECT_SOURCE_DIR}/common_optarg.c
  ${PROJECT_SOURCE_DIR}/dbus.cc
  ${PROJECT_SOURCE_DIR}/default_features.c
  ${PROJECT_SOURCE_DIR}/lib.c
  ${PROJECT_SOURCE_DIR}/libapparmor_re/aare_rules.cc
  ${PROJECT_SOURCE_DIR}/libapparmor_re/chfa.cc
  ${PROJECT_SOURCE_DIR}/libapparmor_re/expr-tree.cc
  ${PROJECT_SOURCE_DIR}/libapparmor_re/hfa.cc
  ${PROJECT_SOURCE_DIR}/mount.cc
  ${PROJECT_SOURCE_DIR}/network.c
  ${PROJECT_SOURCE_DIR}/parser_alias.c
  ${PROJECT_SOURCE_DIR}/parser_common.c
  ${PROJECT_SOURCE_DIR}/parser_include.c
  ${PROJECT_SOURCE_DIR}/parser_interface.c
  ${PROJECT_SOURCE_DIR}/parser_main.c
  ${PROJECT_SOURCE_DIR}/parser_merge.c
  ${PROJECT_SOURCE_DIR}/parser_misc.c
  ${PROJECT_SOURCE_DIR}/parser_policy.c
  ${PROJECT_SOURCE_DIR}/parser_regex.c
  ${PROJECT_SOURCE_DIR}/parser_symtab.c
  ${PROJECT_SOURCE_DIR}/parser_variable.c
  ${PROJECT_SOURCE_DIR}/policy_cache.c
  ${PROJECT_SOURCE_DIR}/profile.cc
  ${PROJECT_SOURCE_DIR}/ptrace.cc
  ${PROJECT_SOURCE_DIR}/rule.cc
  ${PROJECT_SOURCE_DIR}/signal.cc
  ${PROJECT_SOURCE_DIR}/userns.cc
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
set(CMAKE_CXX_FLAGS "-c -Wall -Wextra")
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_C_FLAGS "-c -g -O2 -pipe")

## set_source_files_properties(${SOURCES} PROPERTIES LANGUAGE CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#### Create the library ####
add_executable(${PROJECT_NAME} ${SOURCES} ${BISON_PARSER_OUTPUT_SOURCE} ${FLEX_LEXER_OUTPUTS})

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC ${AUTOGEN_SOURCE_DIR})
