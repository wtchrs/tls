cmake_minimum_required(VERSION 3.28)
project(tls)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    set(CMAKE_CXX_FLAGS "/W4")
else()
    set(CMAKE_CXX_FLAGS "-Wall -Wextra")
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add custom flags
add_compile_definitions(PRINT_LOG)

# Dependencies
find_package(jsoncpp REQUIRED CONFIG)
find_package(spdlog CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)
pkg_check_modules(nettle REQUIRED IMPORTED_TARGET nettle)
pkg_check_modules(hogweed REQUIRED IMPORTED_TARGET hogweed)

# Subdirectories
add_subdirectory(core)
add_subdirectory(protocol)
add_subdirectory(tests)

# Test configurations
include(CTest)
enable_testing()

add_test(NAME Catch2Test
        COMMAND build/tests/tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
