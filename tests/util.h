#ifndef UTIL_H
#define UTIL_H


#include <catch2/catch_test_macros.hpp>

#define REQUIRE_MESSAGE(EXPRESSION, MESSAGE) { INFO(MESSAGE); REQUIRE(EXPRESSION); }

template<typename It>
std::string bytes_to_hex(It begin, It end) {
    std::stringstream ss;
    for (auto it = begin; it != end; ++it) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it) << ':';
    }
    return ss.str();
}


#endif // UTIL_H
