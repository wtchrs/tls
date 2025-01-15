#include <cstdint>
#include <gmpxx.h>
#include <optional>
#include <utility>
#include "tls/aes.h"
#include "tls/cipher_mode.h"
#include "tls/diffie_hellman.h"
#include "tls/mpz.h"
#include "tls/rsa.h"

/**
 * @brief A template class implementing the TLS protocol.
 *
 * This class provides a custom implementation of the TLS protocol,
 * supporting `TLS_ECDHE_RSA_AES128_GCM_SHA256` cipher suite.
 *
 * The class handles both server and client roles,
 * and the mode is determined by the template parameter.
 *
 * @tparam SV Boolean indicating server mode (true) or client mode (false)
 */
template<bool SV = true>
class TLS {
protected:
    GCM<aes128> aes_[2]; ///< GCM mode AES-128 cipher
    mpz_class enc_seq_num_ = 0, dec_seq_num_ = 0; ///< Sequence number for encryption and decryption

    /** secp256r1 elliptic curve parameters */
    ec_field secp256r1_{
            0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC_mpz,
            0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B_mpz,
            0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_mpz
    };
    /** Generator point for the secp256r1 curve */
    ec_point G_{
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296_mpz,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5_mpz, secp256r1_
    };

    mpz_class prv_key_ = random_prime(31); ///< Private key for the curve
    ec_point P_{prv_key_ * G_}; ///< Public key for the curve

    std::array<unsigned char, 32> session_id_, server_random_, client_random_;

    /**
     * @brief Master secret for the session
     *
     * This is obtained from the key exchange.
     */
    std::vector<unsigned char> master_secret_;

    std::string accumulated_handshakes_; ///< Accumulated handshake messages
    static std::string certificate_; ///< Server certificate, read from file
    static rsa_class rsa_; ///< Initialized with public key of the server certificate

public:
    /**
     * @brief Get the content type from the message
     * @param s The message to decode
     * @return A pair of integers representing the content type and the length of the message
     */
    std::pair<int, int> get_content_type(const std::string &s);

    /**
     * @brief Decode the message
     * @param s The message to decode
     * @return The decoded message, or an empty string if the message is not valid
     */
    std::optional<std::string> decode(std::string &&s = "");

    /**
     * @brief Encode the message
     * @param s The message to encode
     * @param type The content type of the message
     * @return The encoded message
     */
    std::string encode(std::string &&s = "", int type = 0x17);

    // ========== FOR HANDSHAKE ==========

    std::string client_hello(std::string &&s = "");
    std::string server_hello(std::string &&s = "");
    std::string server_certificate(std::string &&s = "");
    std::string server_key_exchange(std::string &&s = "");
    std::string server_hello_done(std::string &&s = "");
    std::string client_key_exchange(std::string &&s = "");
    std::string change_cipher_spec(std::string &&s = "");
    std::string finished(std::string &&s = "");

    int alert(std::string &&s = "");
    std::string alert(uint8_t level, uint8_t desc);

protected:
    std::string accumulate(const std::string &s);

private:
    void generate_signature(unsigned char *p_length, unsigned char *p);
    void derive_keys(mpz_class premaster_secret);
};
