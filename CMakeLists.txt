cmake_minimum_required(VERSION 3.28)
project(custom_tls)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(jsoncpp REQUIRED CONFIG)
find_package(Catch2 REQUIRED CONFIG)

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

file(GLOB_RECURSE TEST_SOURCES
        tests/aes.cpp
        tests/base64.cpp
        tests/cert.cpp
        tests/cipher_mode.cpp
        tests/diffie_hellman.cpp
        tests/ecdsa.cpp
        tests/hmac.cpp
        tests/mpz.cpp
        tests/prf.cpp
        tests/rsa.cpp
        tests/sha.cpp
)

add_library(custom_tls STATIC ${SOURCES})
target_include_directories(custom_tls PUBLIC include)
target_link_libraries(custom_tls PRIVATE
        PkgConfig::gmpxx
        PkgConfig::nettle
        PkgConfig::hogweed
        JsonCpp::JsonCpp
)

add_executable(tests ${SOURCES} ${TEST_SOURCES})
target_include_directories(tests PUBLIC include)
target_link_libraries(tests PRIVATE
        PkgConfig::gmpxx
        PkgConfig::nettle
        PkgConfig::hogweed
        JsonCpp::JsonCpp
        Catch2::Catch2
        Catch2::Catch2WithMain
)
target_compile_definitions(tests PRIVATE TESTING)

include(CTest)
enable_testing()

add_test(NAME Catch2Test COMMAND tests)
