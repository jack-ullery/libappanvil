cmake_minimum_required (VERSION 3.16.3)

project (aa-parse C CXX)

#### Set some variables #####
set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/parser)
set(AUTOGEN_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

set(LIBRARY_NAME lib${PROJECT_NAME}-dev)

# Create the directory, so that it exists for FLEX/BISON to use 
file(MAKE_DIRECTORY ${AUTOGEN_SOURCE_DIR})

### Sources that need to be built ###
set(SOURCES
  ${PROJECT_SOURCE_DIR}/lib.c
  ${PROJECT_SOURCE_DIR}/parser_include.c
  ${PROJECT_SOURCE_DIR}/parser_misc.c
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
              ${AUTOGEN_SOURCE_DIR}/parser_yacc.c
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_yacc.h)

#### Flex stuff ####
find_package(FLEX 2.5.5 REQUIRED)

FLEX_TARGET(LEXER 
              ${LEXER_INPUT} 
              ${AUTOGEN_SOURCE_DIR}/parser_lex.cc
              DEFINES_FILE ${AUTOGEN_SOURCE_DIR}/parser_lex.h)

ADD_FLEX_BISON_DEPENDENCY(LEXER PARSER)

#### Set Compiler Options ####
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_C_FLAGS "-g -O2 -pipe")

## set_source_files_properties(${CXX_SOURCES} PROPERTIES LANGUAGE CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#### Create the library ####
add_library(${LIBRARY_NAME} ${SOURCES} ${FLEX_LEXER_OUTPUTS} ${BISON_PARSER_OUTPUT_SOURCE})

target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(${LIBRARY_NAME} PUBLIC ${AUTOGEN_SOURCE_DIR})

#### Create the final executable ####
add_executable(${PROJECT_NAME} ${MAIN_SOURCE})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})
