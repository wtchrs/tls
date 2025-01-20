#include "tls/tls.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gmpxx.h>
#include <ios>
#include <iostream>
#include <ostream>
#include <sstream>
#include <utility>
#include <vector>
#include "tls/base64.h"
#include "tls/cert.h"
#include "tls/der.h"
#include "tls/mpz.h"
#include "tls/rsa.h"

// Pack structs to 1 byte alignment to avoid padding
#pragma pack(push, 1)

struct TLS_header {
    /** 0x15: Alert, 0x16: Handshake, 0x17: Application data */
    uint8_t content_type = tls_type::HANDSHAKE;
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    uint8_t length[2] = {0, 4};

    void set_length(size_t k) {
        length[0] = k / 0x100;
        length[1] = k % 0x100;
    }

    size_t get_length() {
        return length[0] * 0x100 + length[1];
    }
};

struct handshake_header {
    uint8_t handshake_type;
    uint8_t length[3] = {0, 0, 0};

    void set_length(size_t k) {
        length[0] = k / 0x10000;
        length[1] = k % 0x10000 / 0x100;
        length[2] = k % 0x100;
    }

    size_t get_length() {
        return length[0] * 0x10000 + length[1] * 0x100 + length[2];
    }
};

struct hello_common {
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    /** Server random and client random */
    uint8_t random[32];
    uint8_t session_id_length = 32;
    uint8_t session_id[32];
};

struct alert_message {
    /** tls.content_type: 0x15, tls.length: 2 */
    TLS_header tls{.content_type = tls_type::ALERT, .length = {0, 2}};
    uint8_t alert_level;
    uint8_t alert_desc;
};

#pragma pack(pop)

template<typename T>
static std::string struct2str(const T &t) {
    return std::string{reinterpret_cast<char *>(&t), sizeof(t)};
}
// TODO: Implementation for `TLS` in here

template<bool SV>
std::string TLS<SV>::alert(uint8_t level, uint8_t desc) {
    alert_message h{.alert_level = level, .alert_desc = desc};
    return struct2str(h);
}

template<bool SV>
int TLS<SV>::alert(std::string &&s) {
    alert_message *p = reinterpret_cast<alert_message *>(s.data());
    int level, desc;

    if (p->tls.get_length() == 2) {
        // For plain alert message
        level = p->alert_level;
        desc = p->alert_desc;
    } else {
        // For encrypted alert message
        s = decode(s);
        level = static_cast<uint8_t>(s[0]);
        desc = static_cast<uint8_t>(s[1]);
    }

    switch (desc) {
    // Reuse s
    case 0: s = "close_notify(0)"; break;
    case 10: s = "unexpected_message(10)"; break;
    case 20: s = "bad_record_mac(20)"; break;
    case 21: s = "decryption_failed_RESERVED(21)"; break;
    case 22: s = "record_overflow(22)"; break;
    case 30: s = "decompression_failure(30)"; break;
    case 40: s = "handshake_failure(40)"; break;
    case 41: s = "no_certificate_RESERVED(41)"; break;
    case 42: s = "bad_certificate(42)"; break;
    case 43: s = "unsupported_certificate(43)"; break;
    case 44: s = "certificate_revoked(44)"; break;
    case 45: s = "certificate_expired(45)"; break;
    case 46: s = "certificate_unknown(46)"; break;
    case 47: s = "illegal_parameter(47)"; break;
    case 48: s = "unknown_ca(48)"; break;
    case 49: s = "access_denied(49)"; break;
    case 50: s = "decode_error(50)"; break;
    case 51: s = "decrypt_error(51)"; break;
    case 60: s = "export_restriction_RESERVED(60)"; break;
    case 70: s = "protocol_version(70)"; break;
    case 71: s = "insufficient_security(71)"; break;
    case 80: s = "internal_error(80)"; break;
    case 90: s = "user_canceled(90)"; break;
    case 100: s = "no_renegotiation(100)"; break;
    case 110: s = "unsupported_extension(110)"; break;
    }

    if (level == 1 || level == 2) {
        std::cerr << s << std::endl;
    }

    return desc;
}

template<bool SV>
std::string TLS<SV>::accumulate(const std::string &s) {
    accumulated_handshakes_ += s.substr(sizeof(TLS_header));
    return s;
}
