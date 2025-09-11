file(GLOB_RECURSE SOURCES
        src/sha/operations.cpp
        src/aes.cpp
        src/base64.cpp
        src/cert.cpp
        src/der.cpp
        src/diffie_hellman.cpp
        src/ecdsa.cpp
        src/mpz.cpp
        src/rsa.cpp
        src/sha1.cpp
        src/tls12.cpp
        src/tls13.cpp
        src/tls_types.cpp
)

add_library(core STATIC ${SOURCES})

target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(core PUBLIC
        PkgConfig::gmpxx
        PkgConfig::nettle
        PkgConfig::hogweed
        JsonCpp::JsonCpp
)
target_link_libraries(core PRIVATE spdlog::spdlog)
