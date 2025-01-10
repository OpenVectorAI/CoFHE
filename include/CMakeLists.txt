add_library(CoFHE INTERFACE)

find_package(gmp REQUIRED)
find_package(OpenSSL REQUIRED)

set(OPENMP TRUE)

file(GLOB_RECURSE CoFHE_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.inl")
target_sources(
    CoFHE
    INTERFACE
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES ${CoFHE_HEADERS}
)

target_link_libraries(
    CoFHE
    INTERFACE
    $<BUILD_INTERFACE:gmp::gmp>
    $<INSTALL_INTERFACE:gmp::gmp>
    $<BUILD_INTERFACE:OpenSSL::SSL>
    $<INSTALL_INTERFACE:OpenSSL::SSL>
)

target_include_directories(
    CoFHE
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CoFHE_ROOT_DIRECTORY}>/thirdparty/bicycl/src
    $<BUILD_INTERFACE:${CoFHE_ROOT_DIRECTORY}>/thirdparty/json/include
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(CPU_X86_64)
    target_link_libraries(CoFHE
        INTERFACE
        $<BUILD_INTERFACE:bicycl>
        $<INSTALL_INTERFACE:bicycl::bicycl>
    )
endif()

target_compile_definitions(
    CoFHE
    INTERFACE
    $<$<BOOL:${OPENMP}>:OPENMP>
)

target_compile_features(
    CoFHE
    INTERFACE
    cxx_std_20)

target_compile_options(
    CoFHE
    INTERFACE
    $<$<CONFIG:Release>:-O3>
    # $<$<CONFIG:Release>:-Wall>
    # $<$<CONFIG:Release>:-Wextra>
    # $<$<CONFIG:Release>:-Werror>
    $<$<CONFIG:Release>:-Wno-terminate>
    $<$<CONFIG:Release>:-DNDEBUG>
    $<$<CONFIG:Release>:-march=native>
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-ggdb>
)

if (OPENMP)
    find_package(OpenMP REQUIRED)
    if (!OpenMP_CXX_FOUND)
        message(FATAL_ERROR "OpenMP not found")
    endif()
    target_link_libraries(CoFHE INTERFACE OpenMP::OpenMP_CXX)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(
        CoFHE
        INTERFACE
        $<$<CONFIG:Release>:-fno-omit-frame-pointer>
        $<$<CONFIG:Release>:-fno-strict-aliasing>
        $<$<CONFIG:Release>:-funroll-loops>
        $<$<CONFIG:Release>:-Ofast>
    )
endif()

install(
    TARGETS CoFHE
    EXPORT CoFHEConfig
    FILE_SET HEADERS
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CoFHE
)

install(
    EXPORT CoFHEConfig
    FILE CoFHEConfig.cmake
    NAMESPACE CoFHE::
    DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/CoFHE
)