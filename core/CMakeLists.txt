find_package(jsoncpp REQUIRED CONFIG)
find_package(spdlog CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)
pkg_check_modules(nettle REQUIRED IMPORTED_TARGET nettle)
pkg_check_modules(hogweed REQUIRED IMPORTED_TARGET hogweed)

file(GLOB_RECURSE SOURCES
        src/aes.cpp
        src/base64.cpp
        src/cert.cpp
        src/der.cpp
        src/diffie_hellman.cpp
        src/ecdsa.cpp
        src/mpz.cpp
        src/rsa.cpp
        src/sha1.cpp
        src/tls.cpp
)

add_library(core STATIC ${SOURCES})

target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(core PUBLIC
        PkgConfig::gmpxx
        PkgConfig::nettle
        PkgConfig::hogweed
        JsonCpp::JsonCpp
        spdlog::spdlog
)
