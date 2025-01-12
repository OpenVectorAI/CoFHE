cmake_minimum_required(VERSION 3.9)

project(CoFHE VERSION 0.0.1 LANGUAGES CXX)

include(GNUInstallDirs)

set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake.utils")
list (APPEND CMAKE_MODULE_PATH "${MODULE_DIR}")
set (CoFHE_ROOT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif()

set(JSON_Install ON)
add_subdirectory(thirdparty/json)
add_subdirectory(thirdparty/bicycl)
add_subdirectory(include)
add_subdirectory(benchmarks EXCLUDE_FROM_ALL)
add_subdirectory(examples EXCLUDE_FROM_ALL)