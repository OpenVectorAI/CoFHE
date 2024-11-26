include_directories(${CMAKE_SOURCE_DIR}/include)
add_custom_target(cofhe_benchmarks COMMAND ${CMAKE_COMMAND} -E echo "Build all examples")

add_executable(local local.cpp)
target_link_libraries(local PUBLIC CoFHE)
add_dependencies(cofhe_benchmarks local)

add_executable(network network.cpp)
target_link_libraries(network PUBLIC CoFHE)
add_dependencies(cofhe_benchmarks network)