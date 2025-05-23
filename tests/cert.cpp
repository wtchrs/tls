#include "core/cert.h"
#include "core/base64.h"
#include "core/der.h"
#include "util.h"

#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ostream>
#include <spdlog/spdlog.h>
#include <sstream>

TEST_CASE("Get certificate core") {
    std::string expected = "HERE_COMES_CERTIFICATE_CORE";

    std::stringstream ss;
    ss << "Lines here are ignored." << std::endl
       << "-----BEGIN CERTIFICATE-----" << std::endl
       << expected << std::endl
       << "-----END CERTIFICATE-----" << std::endl;

    auto core = get_certificate_core(ss);

    if (core.compare(expected) != 0) {
        EXPECTED(expected, core);
    }
}

TEST_CASE("Parse integer DER") {
    const std::string expected = "2a:";
    const char *der_str = "\x02\x01\x2a";
    std::istringstream iss{std::string{der_str}};

    auto parsed = der2json(iss);

    if (!parsed) {
        FAIL("Failed to parse.");
    }

    spdlog::debug("Parsed JSON value: {}", parsed->toStyledString());

    auto str = (*parsed)[0].asString();
    if (str.compare(expected) != 0) {
        EXPECTED(expected, str);
    }
}

TEST_CASE("Parse certificate in file as JSON value") {
    spdlog::info("Current path: {}", std::filesystem::current_path().string());
    const char *cert_file = "./cert/example/server-cert.pem";
    std::ifstream f(cert_file);
    if (!f.is_open()) {
        FAIL("Failed to open certificate file: " << cert_file);
    }
    std::string s = get_certificate_core(f);
    auto v = base64_decode(s);
    std::stringstream ss;
    for (uint8_t c : v) {
        ss << c;
    }
    spdlog::debug("Decoded string: {}", bytes_to_hex(v.cbegin(), v.cend()));
    auto jsonValue = der2json(ss);
    if (jsonValue.has_value()) {
        spdlog::debug("JSON form of the parsed certificate: {}", (*jsonValue).toStyledString());
    } else {
        FAIL("Failed to parse certificate.");
    }
}
