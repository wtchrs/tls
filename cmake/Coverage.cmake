function(enable_coverage_flags)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "Coverage requires GCC or Clang")
    endif()

    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endfunction()

function(add_lcov_coverage_target)
    find_program(LCOV_EXECUTABLE lcov REQUIRED)
    find_program(GENHTML_EXECUTABLE genhtml REQUIRED)
    find_program(GCOV_EXECUTABLE gcov REQUIRED)

    set(COVERAGE_DIR ${CMAKE_BINARY_DIR}/coverage)
    set(BASE_INFO ${COVERAGE_DIR}/base.info)
    set(TEST_INFO ${COVERAGE_DIR}/test.info)
    set(TOTAL_INFO ${COVERAGE_DIR}/total.info)
    set(FILTERED_INFO ${COVERAGE_DIR}/filtered.info)
    set(HTML_DIR ${COVERAGE_DIR}/html)

    add_custom_target(coverage
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${COVERAGE_DIR}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${COVERAGE_DIR}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Reset counters"
        COMMAND ${LCOV_EXECUTABLE}
            --zerocounters
            --directory ${CMAKE_BINARY_DIR}
            --gcov-tool ${GCOV_EXECUTABLE}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Capture initial baseline"
        COMMAND ${LCOV_EXECUTABLE}
            --capture
            --initial
            --directory ${CMAKE_BINARY_DIR}
            --base-directory ${CMAKE_SOURCE_DIR}
            --gcov-tool ${GCOV_EXECUTABLE}
            --ignore-errors source
            --output-file ${BASE_INFO}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Run tests"
        COMMAND ${CMAKE_CTEST_COMMAND}
            --test-dir ${CMAKE_BINARY_DIR}
            --output-on-failure

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Capture test coverage"
        COMMAND ${LCOV_EXECUTABLE}
            --capture
            --directory ${CMAKE_BINARY_DIR}
            --base-directory ${CMAKE_SOURCE_DIR}
            --gcov-tool ${GCOV_EXECUTABLE}
            --ignore-errors source
            --output-file ${TEST_INFO}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Merge tracefiles"
        COMMAND ${LCOV_EXECUTABLE}
            --add-tracefile ${BASE_INFO}
            --add-tracefile ${TEST_INFO}
            --output-file ${TOTAL_INFO}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Filter project sources"
        COMMAND ${LCOV_EXECUTABLE}
            --extract ${TOTAL_INFO}
            "${CMAKE_SOURCE_DIR}/core/src/*"
            "${CMAKE_SOURCE_DIR}/core/include/*"
            --output-file ${FILTERED_INFO}

        COMMAND ${CMAKE_COMMAND} -E echo "[coverage] Generate HTML report"
        COMMAND ${GENHTML_EXECUTABLE}
            ${FILTERED_INFO}
            --output-directory ${HTML_DIR}
            --demangle-cpp

        COMMAND ${CMAKE_COMMAND}
            -E echo "[coverage] HTML report: ${HTML_DIR}/index.html"

        DEPENDS tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating lcov HTML coverage report"
        VERBATIM
    )
endfunction()
