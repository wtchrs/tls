file(GLOB_RECURSE SOURCES
        src/acceptor.cpp
        src/address_util.cpp
        src/connector.cpp
        src/layer.cpp
)

add_library(tcp ${SOURCES})
target_include_directories(tcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tcp PUBLIC core)
target_link_libraries(tcp PRIVATE spdlog::spdlog)

add_executable(client_notls example/client_notls.cpp)
target_link_libraries(client_notls PRIVATE tcp spdlog::spdlog)
add_executable(server_notls example/server_notls.cpp)
target_link_libraries(server_notls PRIVATE tcp spdlog::spdlog)

add_executable(client_tls example/client_tls.cpp)
target_link_libraries(client_tls PRIVATE tcp spdlog::spdlog)
add_executable(server_tls example/server_tls.cpp)
target_link_libraries(server_tls PRIVATE tcp spdlog::spdlog)
