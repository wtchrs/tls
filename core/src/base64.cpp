#include "core/base64.h"

static char b2c(const unsigned char n) {
    if (n < 26)
        return 'A' + n;
    if (n < 52)
        return 'a' + n - 26;
    if (n < 62)
        return '0' + n - 52;
    return n == 62 ? '+' : '/';
}

static char c2b(const char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    return c == '+' ? 62 : 63;
}

std::string base64_encode(std::vector<unsigned char> v) {
    std::string s;
    const size_t padding = (3 - v.size() % 3) % 3;
    for (size_t i = 0; i < padding; ++i) {
        v.push_back(0);
    }
    for (size_t i = 0; i < v.size(); i += 3) {
        s += b2c(v[i] >> 2);
        s += b2c((v[i] & 0x03) << 4 | v[i + 1] >> 4);
        s += b2c((v[i + 1] & 0x0f) << 2 | v[i + 2] >> 6);
        s += b2c(v[i + 2] & 0x3f);
    }
    for (size_t i = 0; i < padding; ++i) {
        s[s.size() - 1 - i] = '=';
    }
    return s;
}

std::vector<unsigned char> base64_decode(const std::string &s) {
    std::vector<unsigned char> v{};
    size_t padding = 0;
    for (auto p = s.crbegin(), end = s.crend(); p < end && *p == '='; ++p) {
        ++padding;
    }
    unsigned char bit[4];
    for (size_t i = 0; i < s.size(); i += 4) {
        for (size_t j = 0; j < 4; ++j)
            bit[j] = c2b(s[i + j]);
        v.push_back(bit[0] << 2 | bit[1] >> 4);
        v.push_back(bit[1] << 4 | bit[2] >> 2);
        v.push_back(bit[2] << 6 | bit[3]);
    }
    for (size_t i = 0; i < padding; ++i) {
        v.pop_back();
    }
    return v;
}
