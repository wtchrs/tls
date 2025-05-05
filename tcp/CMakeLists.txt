file(GLOB_RECURSE SOURCES
        src/http.cpp
        src/tcp.cpp
        src/tls.cpp
)

add_library(tcp ${SOURCES})
target_include_directories(tcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tcp PRIVATE core)

add_executable(client_notls src/app/client_notls.cpp)
target_link_libraries(client_notls PRIVATE tcp)
add_executable(server_notls src/app/server_notls.cpp)
target_link_libraries(server_notls PRIVATE tcp)
