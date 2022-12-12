cmake_minimum_required (VERSION 3.16.3)

project(${PROJECT_NAME}-test C CXX)

set(TEST_SOURCES ./src/main.cc)
set(TEST_PROJECT_NAME ${PROJECT_NAME})

#### Create the final executable ####
add_executable(${PROJECT_NAME} ${TEST_SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARY_NAME})
