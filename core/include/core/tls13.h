#ifndef CORE_TLS13_H
#define CORE_TLS13_H


#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <gmpxx.h>
#include <optional>
#include <vector>
#include "core/hkdf.h"
#include "core/sha/sha2.h"
#include "core/tls12.h"

template<bool SV>
class TLS13 : public TLS12<SV> {
public:
    static constexpr std::string INTERMEDIATE_DERIVATION_LABEL = "derived",
                                 CLIENT_HANDSHAKE_TRAFFIC_LABEL = "c hs traffic",
                                 SERVER_HANDSHAKE_TRAFFIC_LABEL = "s hs traffic",
                                 CLIENT_APPLICATION_TRAFFIC_LABEL = "c ap traffic",
                                 SERVER_APPLICATION_TRAFFIC_LABEL = "s ap traffic";

protected:
    HKDF<SHA256> hkdf_;

    /** If TLS 1.3, it has non-zero value after client/server hello message. */
    mpz_class shared_secret_;

private:
    static std::string ecdsa_certificate_;

    uint8_t prv_[32], echo_id_[32];

    std::array<std::vector<uint8_t>, 2> finished_key_;

public:
    std::string client_hello(std::string &&s = "");
    std::string server_hello(std::string &&s = "");

    bool handshake(std::function<std::optional<std::string>()> &read_f, std::function<void(std::string)> &write_f);

    std::string finished(std::string &&s = "");
    std::string certificate_verify();
    std::optional<std::string> decode(std::string &&s);
    std::string encode(std::string &&s, int type = 23);
    std::string server_certificate13();

protected:
    std::string client_ext();
    std::string server_ext();

    std::string encrypted_extention();

    bool client_ext(unsigned char *p);
    bool server_ext(unsigned char *p);

private:
    void protect_data();
    void protect_handshake();
    std::array<std::vector<uint8_t>, 2>
    set_aes(std::vector<uint8_t> salt, std::string client_label, std::string server_label);

    bool supported_group(unsigned char *p, size_t len);
    bool ec_point_format(unsigned char *p, size_t len);
    bool sub_key_share(unsigned char *p);
    bool key_share(unsigned char *p, size_t len);
    bool supported_version(unsigned char *p, size_t len);

    void derive_keys(mpz_class premaster_secret);
    std::optional<std::string> decode13(std::string &&s);
    std::string encode13(std::string &&s, int type = 23);
};


#endif
