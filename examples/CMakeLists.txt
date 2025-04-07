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

add_executable(binary_scheme binary_scheme.cpp)
target_link_libraries(binary_scheme PRIVATE CoFHE)
add_dependencies(cofhe_examples binary_scheme)

add_executable(native_comparision native_comparision.cpp)
target_link_libraries(native_comparision PRIVATE CoFHE)
add_dependencies(cofhe_examples native_comparision) 

add_executable(reencryption reencryption.cpp)
target_link_libraries(reencryption PRIVATE CoFHE)
add_dependencies(cofhe_examples reencryption)

add_executable(transfer_sim transfer_sim.cpp)
target_link_libraries(transfer_sim PRIVATE CoFHE)
add_dependencies(cofhe_examples transfer_sim)