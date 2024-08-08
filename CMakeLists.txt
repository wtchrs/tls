cmake_minimum_required(VERSION 3.28)
project(custom_tls)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif ()

find_package(PkgConfig REQUIRED)

pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)
pkg_check_modules(nettle REQUIRED IMPORTED_TARGET nettle)
pkg_check_modules(hogweed REQUIRED IMPORTED_TARGET hogweed)

find_package(jsoncpp REQUIRED CONFIG)

find_package(Catch2 REQUIRED CONFIG)

file(GLOB_RECURSE SOURCES
        src/diffie_hellman.cc
        src/ecdsa.cc
        src/mpz.cc
        src/rsa.cc
)

add_library(custom_tls STATIC ${SOURCES})

target_include_directories(custom_tls PUBLIC include)

target_link_libraries(custom_tls PRIVATE
        PkgConfig::gmpxx
        PkgConfig::nettle
        PkgConfig::hogweed
        JsonCpp::JsonCpp
)

file(GLOB_RECURSE TEST_SOURCES
        tests/test.cc
        tests/ecdsa.cc
)

add_executable(catch2-test ${TEST_SOURCES})

add_dependencies(catch2-test custom_tls)

target_link_libraries(catch2-test PRIVATE
        custom_tls
        PkgConfig::nettle
        PkgConfig::hogweed
        Catch2::Catch2
        Catch2::Catch2WithMain
)

include(CTest)
enable_testing()

add_test(NAME Catch2Test COMMAND catch2-test)
