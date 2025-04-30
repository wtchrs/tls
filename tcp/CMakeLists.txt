file(GLOB_RECURSE SOURCES
        src/http.cpp
        src/tcp.cpp
)

add_library(tcp ${SOURCES})
target_include_directories(tcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tcp PRIVATE core)

add_executable(client_nocrypt src/nocrypt/client_nocrypt.cpp)
target_link_libraries(client_nocrypt PRIVATE tcp)
add_executable(server_nocrypt src/nocrypt/server_nocrypt.cpp)
target_link_libraries(server_nocrypt PRIVATE tcp)
