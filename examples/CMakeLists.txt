include_directories(${CMAKE_SOURCE_DIR}/include)
add_custom_target(cofhe_examples COMMAND ${CMAKE_COMMAND} -E echo "Build all examples")

add_executable(node node.cpp)
target_link_libraries(node PUBLIC CoFHE)
add_dependencies(cofhe_examples node)
add_test(node_test node)

add_executable(tutorial tutorial.cpp)
target_link_libraries(tutorial PUBLIC CoFHE)
add_dependencies(cofhe_examples tutorial)