add_custom_target(cofhe_benchmarks COMMAND ${CMAKE_COMMAND} -E echo "Build all examples")

add_executable(local local.cpp)
target_link_libraries(local PRIVATE CoFHE)
add_dependencies(cofhe_benchmarks local)

add_executable(network network.cpp)
target_link_libraries(network PRIVATE CoFHE)
add_dependencies(cofhe_benchmarks network)