#include "core/cert.h"
#include <array>
#include <gmpxx.h>
#include <iomanip>
#include <json/value.h>
#include <optional>
#include <sstream>
#include <string>
#include "core/base64.h"
#include "core/der.h"

std::string get_certificate_core(std::istream &is) {
    std::string s, r;
    while (s != "-----BEGIN")
        if (!(is >> s))
            return r;
    std::getline(is, s);
    for (is >> s; s != "-----END"; is >> s)
        r += s;
    return r;
}

std::optional<Json::Value> pem2json(std::istream &is) {
    auto v = base64_decode(get_certificate_core(is));
    std::stringstream ss;
    for (auto c : v) {
        ss << c;
    }
    return der2json(ss);
}

mpz_class str2mpz(const std::string &s) {
    std::stringstream ss{s};
    std::string r = "0x";
    char c;
    for (std::string in; ss >> std::setw(2) >> in >> c;) {
        r += in;
    }
    return mpz_class{r};
}

static std::optional<std::array<mpz_class, 2>> process_bitstring(const std::string &s) {
    std::stringstream ss{s}, ss2;
    std::string str;
    char c;
    ss >> std::setw(2) >> str >> c; // Ignore first byte
    while (ss >> std::setw(2) >> str >> c) {
        c = std::stoi(str, nullptr, 16);
        ss2 << c;
    }
    auto opt_val = der2json(ss2);
    if (!opt_val) {
        return std::nullopt;
    }
    // Extract RSA modulus and exponent
    return {{str2mpz((*opt_val)[0][0].asString()), str2mpz((*opt_val)[0][1].asString())}};
}

std::optional<std::array<mpz_class, 3>> get_pubkeys(std::istream &is) {
    auto opt_value = pem2json(is);
    if (!opt_value) {
        return std::nullopt;
    }
    return get_pubkeys(*opt_value);
}

std::optional<std::array<mpz_class, 3>> get_pubkeys(Json::Value &value) {
    auto processed = process_bitstring(value[0][0][6][1].asString());
    if (!processed) {
        return std::nullopt;
    }
    auto [K, e] = *processed;
    auto signature = str2mpz(value[0][2].asString());
    return {{K, e, signature}};
}

std::optional<std::array<mpz_class, 3>> get_keys(std::istream &is) {
    auto opt_value = pem2json(is);
    if (!opt_value) {
        return std::nullopt;
    }
    return get_keys(*opt_value);
}

std::array<mpz_class, 3> get_keys(const Json::Value &value) {
    return {
            str2mpz(value[0][1].asString()),
            str2mpz(value[0][2].asString()),
            str2mpz(value[0][3].asString()),
    };
}
