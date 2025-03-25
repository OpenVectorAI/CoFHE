add_custom_target(cofhe_examples COMMAND ${CMAKE_COMMAND} -E echo "Build all examples")

add_executable(node node.cpp)
target_link_libraries(node PRIVATE CoFHE)
add_dependencies(cofhe_examples node)

add_executable(tutorial tutorial.cpp)
target_link_libraries(tutorial PRIVATE CoFHE)
add_dependencies(cofhe_examples tutorial)

add_executable(linear_regression linear_regression.cpp)
target_link_libraries(linear_regression PRIVATE CoFHE)
add_dependencies(cofhe_examples linear_regression)

add_executable(vector_search vector_search.cpp)
target_link_libraries(vector_search PRIVATE CoFHE)
add_dependencies(cofhe_examples vector_search)

add_executable(comparison comparison.cpp)
target_link_libraries(comparison PRIVATE CoFHE)
add_dependencies(cofhe_examples comparison)