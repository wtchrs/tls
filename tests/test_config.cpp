#include <catch2/internal/catch_test_run_info.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <spdlog/cfg/env.h>

struct TestListener : Catch::EventListenerBase {
    using Catch::EventListenerBase::EventListenerBase;

    // NOLINTNEXTLINE(clang-diagnostic-unused-parameter)
    void testRunStarting(const Catch::TestRunInfo &test_run_info) override {
        spdlog::cfg::load_env_levels();
    }
};

CATCH_REGISTER_LISTENER(TestListener)
