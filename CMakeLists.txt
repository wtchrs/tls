cmake_minimum_required(VERSION 3.28)
project(tls)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(cmake/Coverage.cmake)

# Add custom flags
add_compile_definitions(PRINT_LOG)

# Dependencies
find_package(jsoncpp REQUIRED CONFIG)
find_package(spdlog CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)
pkg_check_modules(nettle REQUIRED IMPORTED_TARGET nettle)
pkg_check_modules(hogweed REQUIRED IMPORTED_TARGET hogweed)

# Test coverage
option(ENABLE_COVERAGE "Enable coverage instrumentation" OFF)

if(ENABLE_COVERAGE)
    enable_coverage_flags()
endif()

# Subdirectories
add_subdirectory(core)
add_subdirectory(protocol)

# Install
install(TARGETS core protocol
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY core/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY protocol/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Test configurations
include(CTest)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)

    add_test(NAME Catch2Test
        COMMAND $<TARGET_FILE:tests>
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    if(ENABLE_COVERAGE)
        add_lcov_coverage_target()
    endif()
endif()
