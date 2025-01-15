#include "tls/tls.h"
#include <cstddef>
#include <cstdint>

// Pack structs to 1 byte alignment to avoid padding
#pragma pack(push, 1)

struct TLS_header {
    uint8_t content_type = 0x16; ///< 0x16: Handshake, 0x17: Application data
    uint8_t version[2] = {0x03, 0x03}; ///< 0x0303 for TLS 1.2
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

struct hello_header {
    uint8_t version[2] = {0x03, 0x03}; ///< 0x0303 for TLS 1.2
    uint8_t random[32]; ///< Server random and client random
    uint8_t session_id_length = 32;
    uint8_t session_id[32];
};

#pragma pack(pop)

// TODO: Implementation for `TLS` in here
