cmake_minimum_required (VERSION 3.16.3)

#### Add tests ####
set(PROFILE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/example_profiles)

file(GLOB_RECURSE 
     TEST_PROFILES 
     ${PROFILE_SOURCE_DIR}/*/*.sd
)

add_subdirectory(simple)
add_subdirectory(e2e)