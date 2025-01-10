//
// Created by wtchr on 8/20/2024.
//

#ifndef DER_H
#define DER_H

#include <istream>
#include <json/json.h>
#include <optional>


namespace der {

    enum der_tag {
        EOC = 0,
        BOOLEAN = 1,
        INTEGER = 2,
        BIT_STRING = 3,
        OCTET_STRING = 4,
        NULL_TYPE = 5,
        OBJECT_IDENTIFIER = 6,
        OBJECT_DESCRIPTOR = 7,
        EXTERNAL = 8,
        REAL = 9,
        ENUMERATED = 10,
        EMBEDDED_PDV = 11,
        UTF8STRING = 12,
        RELATIVE_OID = 13,
        SEQUENCE = 16,
        SET = 17,
        NUMERIC_STRING = 18,
        PRINTABLE_STRING = 19,
        T61_STRING = 20,
        VIDEOTEX_STRING = 21,
        IA5_STRING = 22,
        UTC_TIME = 23,
        GENERALIZED_TIME = 24,
        GRAPHIC_STRING = 25,
        VISIBLE_STRING = 26,
        GENERAL_STRING = 27,
        UNIVERSAL_STRING = 28,
        CHARACTER_STRING = 29,
        BMP_STRING = 30
    };

    enum der_class { UNIVERSAL = 0, APPLICATION = 1, CONTEXT_SPECIFIC = 2, PRIVATE = 3 };

    enum der_pc { PRIMITIVE = 0, CONSTRUCTED = 1 };

    struct der_type {
        der_class cls;
        der_pc pc;
        der_tag tag;
    };

} // namespace der


std::optional<Json::Value> der2json(std::istream &is);


#endif
