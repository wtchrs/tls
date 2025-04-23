find_package(Catch2 REQUIRED CONFIG)

file(GLOB_RECURSE TEST_SOURCES
        aes.cpp
        base64.cpp
        cert.cpp
        cipher_mode.cpp
        diffie_hellman.cpp
        ecdsa.cpp
        hmac.cpp
        mpz.cpp
        prf.cpp
        rsa.cpp
        sha.cpp
        tls.cpp
)

add_executable(tests ${TEST_SOURCES})
target_include_directories(tests PUBLIC include)
target_link_libraries(tests PRIVATE
        core
        Catch2::Catch2
        Catch2::Catch2WithMain
)
target_compile_definitions(tests PRIVATE TESTING)

# include(CTest)
# enable_testing()
#
# add_test(NAME Catch2Test COMMAND tests)
