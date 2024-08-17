cmake_minimum_required (VERSION 3.16.3)

#### Add tests ####
set(PROFILE_SOURCE_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/example_profiles)
set(ADDITIONAL_PROFILE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/additional_profiles)

file(GLOB_RECURSE 
     TEST_PROFILES 
     ${PROFILE_SOURCE_DIR}/*/*.sd
     ${ADDITIONAL_PROFILE_SOURCE_DIR}/*/*.sd
)

# Add tests if CMake version is at least 3.19
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.19.0")
     add_subdirectory(simple)
     add_subdirectory(unit)
endif()