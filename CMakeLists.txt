cmake_minimum_required(VERSION 3.9)

project(CoFHE VERSION 0.0.1 LANGUAGES CXX)

set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake.utils")
list (APPEND CMAKE_MODULE_PATH "${MODULE_DIR}")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif()


set (CPU_X86_64 TRUE)
set (CUDA FALSE)
set (OPENMP TRUE)

find_package (gmp REQUIRED)
find_package (OpenSSL REQUIRED)

include (CTest)

if(CPU_X86_64)
    set(CXX "g++")
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    set(CMAKE_CXX_FLAGS_RELEASE "-ffast-math -Ofast -march=native -flto -fuse-linker-plugin -funroll-loops  -fno-omit-frame-pointer -DNDEBUG -Wno-terminate") # -Wextra -Wall -Werror
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -ggdb -fconcepts-diagnostics-depth=3 -Wno-terminate")#  -Wextra -Wall -Werror

    if (OPENMP)
        add_definitions(-DOPENMP)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fopenmp")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fopenmp")
    endif()

    add_subdirectory(thirdparty/bicycl)
elseif (CUDA)
    set (CXX "nvcc")
    set (CMAKE_CXX_STANDARD 20)
    set (CMAKE_CXX_STANDARD_REQUIRED ON)

    set (CMAKE_CXX_FLAGS_RELEASE "-O3 -mark=native -DNDEBUG -Wextra")
    set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g -Wextra -Wall -Werror")
endif()

add_subdirectory(include)
add_subdirectory(benchmarks)
add_subdirectory(examples)
