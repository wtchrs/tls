#include "tls/der.h"

#include <ios>
#include <istream>
#include <json/json.h>
#include <optional>
#include <vector>
#include "tls/mpz.h"

static der::Type read_type(const unsigned char c);
static std::optional<size_t> read_length(std::istream &is);
static std::optional<std::vector<unsigned char>> read_value(std::istream &is, const size_t len);
static Json::Value type_change(const der::Tag tag, std::vector<unsigned char> v);
static std::optional<Json::Value> read_sub_value(std::istream &is, der::PC pc, der::Tag tag, const size_t len);
static std::optional<Json::Value> read_constructed(std::istream &is, const size_t len);

std::optional<Json::Value> der2json(std::istream &is) {
    Json::Value json_value;
    unsigned char c;

    while (is >> std::noskipws >> c) {
        auto [cls, pc, tag] = read_type(c);

        auto opt_l = read_length(is);
        if (!opt_l) {
            return std::nullopt;
        }

        std::optional<Json::Value> sub_value = read_sub_value(is, pc, tag, *opt_l);
        if (!sub_value) {
            return std::nullopt;
        }

        json_value.append(*sub_value);
    }

    return json_value;
}

static std::optional<Json::Value> read_constructed(std::istream &is, const size_t len) {
    Json::Value json_value;
    const size_t start_pos = is.tellg();

    while (static_cast<int>(is.tellg()) - start_pos < len) {
        unsigned char c;
        if (!(is >> std::noskipws >> c)) {
            return std::nullopt;
        }

        auto [cls, pc, tag] = read_type(c);

        auto opt_l = read_length(is);
        if (!opt_l) {
            return std::nullopt;
        }

        auto sub_value = read_sub_value(is, pc, tag, *opt_l);
        if (!sub_value) {
            return std::nullopt;
        }

        json_value.append(*sub_value);
    }
    return json_value;
}

static der::Type read_type(const unsigned char c) {
    return {
            static_cast<der::Class>((c & 0xc0) >> 6),
            static_cast<der::PC>((c & 0x20) >> 5),
            static_cast<der::Tag>(c & 0x1f),
    };
}

static std::optional<size_t> read_length(std::istream &is) {
    unsigned char c;
    if (!(is >> std::noskipws >> c)) {
        return std::nullopt;
    }
    if (c & 0x80) {
        std::vector<unsigned char> v;
        for (int i = 0, j = c & 0x7f; i < j; ++i) {
            is >> c;
            v.push_back(c);
        }
        return bnd2mpz(v.begin(), v.end()).get_si();
    }
    return c;
}

static std::optional<std::vector<unsigned char>> read_value(std::istream &is, const size_t len) {
    unsigned char c;
    std::vector<unsigned char> v{};
    v.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        if (!(is >> std::noskipws >> c)) {
            return std::nullopt;
        }
        v.push_back(c);
    }
    return v;
}

static std::optional<Json::Value> read_sub_value(std::istream &is, der::PC pc, der::Tag tag, const size_t len) {
    if (pc != der::PRIMITIVE) {
        return read_constructed(is, len);
    }

    auto vec = read_value(is, len);
    if (!vec) {
        return std::nullopt;
    }
    return type_change(tag, *vec);
}

static Json::Value type_change(const der::Tag tag, std::vector<unsigned char> v) {
    switch (tag) {
    case der::EOC:
    case der::BOOLEAN:
        return v[0] ? true : false;

    case der::INTEGER:
    case der::BIT_STRING:
    case der::OCTET_STRING:
    case der::NUMERIC_STRING:
    case der::OBJECT_IDENTIFIER:
    case der::OBJECT_DESCRIPTOR: {
        std::stringstream ss;
        for (auto c : v) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(c) << ':';
        }
        std::string result = ss.str();
        return result;
    }

    case der::NULL_TYPE:
        return "null";

    case der::EXTERNAL:
    case der::REAL:
        return *reinterpret_cast<float *>(v.data());

    case der::ENUMERATED:
    case der::EMBEDDED_PDV:
    case der::RELATIVE_OID:
    default: {
        std::stringstream ss;
        for (auto c : v)
            ss << c;
        return ss.str();
    }
    }
}
