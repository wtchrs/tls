file(GLOB_RECURSE SOURCES src/*)

add_library(protocol ${SOURCES})
target_include_directories(protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(protocol PUBLIC core)
target_link_libraries(protocol PRIVATE spdlog::spdlog)

add_executable(client_notls example/client_notls.cpp)
target_link_libraries(client_notls PRIVATE protocol spdlog::spdlog)
add_executable(server_notls example/server_notls.cpp)
target_link_libraries(server_notls PRIVATE protocol spdlog::spdlog)

add_executable(client_tls example/client_tls.cpp)
target_link_libraries(client_tls PRIVATE protocol spdlog::spdlog)
add_executable(server_tls example/server_tls.cpp)
target_link_libraries(server_tls PRIVATE protocol spdlog::spdlog)
