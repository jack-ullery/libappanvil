project(aa-replace)
cmake_minimum_required (VERSION 3.16.3)

set(
  CALLER_SOURCES
  ./src/aa-replace.cc
  ./src/main.cc
)

#====================================

find_package(PkgConfig)
pkg_check_modules(GLIBMM glibmm-2.4 REQUIRED)

#====================================

message(STATUS "Adding aa-replace to build")

set(CALLER_LIBRARY_NAME ${PROJECT_NAME}_dev)
add_library(${CALLER_LIBRARY_NAME} STATIC ${CALLER_SOURCES})

target_include_directories(${CALLER_LIBRARY_NAME} SYSTEM PUBLIC ${GLIBMM_INCLUDE_DIRS})

target_link_libraries(${CALLER_LIBRARY_NAME} PUBLIC ${GLIBMM_LIBRARIES})
target_link_libraries(${CALLER_LIBRARY_NAME} PUBLIC pthread)

add_executable(${PROJECT_NAME} ./src/main.cc)
target_link_libraries(${PROJECT_NAME} PUBLIC ${CALLER_LIBRARY_NAME})

#### Create install target to install binaries  ####
install(
  TARGETS ${PROJECT_NAME}
  DESTINATION bin
)