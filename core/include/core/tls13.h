#ifndef CORE_TLS13_H
#define CORE_TLS13_H


#include <array>
#include <cstddef>
#include <cstdint>
#include <gmpxx.h>
#include <optional>
#include <string_view>
#include <vector>
#include "core/hkdf.h"
#include "core/sha/sha2.h"
#include "core/tls12.h"

/**
 * @brief A template class implementing the TLS 1.3 protocol.
 *
 * This class extends the TLS12 implementation to support TLS 1.3 features.
 * It handles both server and client roles, determined by the template parameter.
 *
 * @tparam SV Boolean indicating server mode (true) or client mode (false).
 */
template<bool SV>
class TLS13 : public TLS12<SV> {
public:
    /** @brief Labels for HKDF key derivation in TLS 1.3. */
    static constexpr std::string_view INTERMEDIATE_DERIVATION_LABEL = "derived",
                                      CLIENT_HANDSHAKE_TRAFFIC_LABEL = "c hs traffic",
                                      SERVER_HANDSHAKE_TRAFFIC_LABEL = "s hs traffic",
                                      CLIENT_APPLICATION_TRAFFIC_LABEL = "c ap traffic",
                                      SERVER_APPLICATION_TRAFFIC_LABEL = "s ap traffic";

protected:
    /** @brief HKDF instance with SHA256 for key derivation. */
    HKDF<SHA256> hkdf_;

    /**
     * @brief The shared secret from the key exchange.
     * @details If TLS 1.3 is used, this has a non-zero value after the client/server hello message.
     */
    mpz_class shared_secret_;

private:
    /** @brief The ECDSA certificate for the server. */
    static std::string ecdsa_certificate_;

    /** @brief Private key for Curve25519 and session ID from client hello. */
    uint8_t prv_[32], echo_id_[32];

    /** @brief Keys used to verify the finished messages. */
    std::array<std::vector<uint8_t>, 2> finished_key_;

public:
    bool is_tls13() {
        return shared_secret_ != 0;
    }
    /**
     * @brief Performs the TLS 1.3 handshake.
     *
     * This method orchestrates the handshake process for both client and server,
     * handling the exchange of messages to establish a secure session.
     *
     * @return True if the handshake was successful, false otherwise.
     */
    bool handshake();

    /**
     * @brief Derives and sets the handshake traffic keys.
     * This is called after the ServerHello message is processed.
     */
    void protect_handshake();

    /**
     * @brief Derives and sets the application traffic keys.
     * This is called after the server's Finished message is processed.
     */
    void protect_data();

    /**
     * @brief Handles or generates a ClientHello message.
     *
     * In server mode, it processes the received ClientHello.
     * In client mode, it generates and returns a ClientHello message.
     *
     * @param s The received ClientHello message (server mode).
     * @return An alert message on error, or an empty string on success (server mode).
     *         The generated ClientHello message (client mode).
     */
    std::string client_hello(std::string &&s = "");

    /**
     * @brief Handles or generates a ServerHello message.
     *
     * In client mode, it processes the received ServerHello.
     * In server mode, it generates and returns a ServerHello message.
     *
     * @param s The received ServerHello message (client mode).
     * @return An alert message on error, or an empty string on success (client mode).
     *         The generated ServerHello message (server mode).
     */
    std::string server_hello(std::string &&s = "");

    /**
     * @brief Generates the EncryptedExtensions message.
     * @return The EncryptedExtensions message.
     */
    std::string encrypted_extension();

    /**
     * @brief Handles or generates a Finished message.
     *
     * This message provides authentication for the handshake.
     * When `s` is empty, it generates a Finished message.
     * Otherwise, it verifies the received Finished message `s`.
     *
     * @param s The received Finished message to verify.
     * @return The generated Finished message, or an empty string if verification is successful.
     *         Returns an alert message on verification failure.
     */
    std::string finished(std::string &&s = "");

    /**
     * @brief Generates the server's Certificate message for TLS 1.3.
     * @return The Certificate message.
     */
    std::string server_certificate13();

    /**
     * @brief Generates a CertificateVerify message.
     *
     * In TLS 1.3, this message proves ownership of the private key for the certificate.
     * In this implementation, it only used in the server(mTLS is not supported).
     *
     * @return The generated CertificateVerify message.
     */
    std::string certificate_verify();

    /**
     * @brief Decodes an incoming TLS record.
     *
     * Overrides TLS12::decode to handle TLS 1.3 record decryption if a
     * TLS 1.3 session is established.
     *
     * @param s The TLS record to decode.
     * @return The decrypted application data, or an empty optional on error.
     */
    std::optional<std::string> decode(std::string &&s);

    /**
     * @brief Encodes an outgoing application data message.
     *
     * Overrides TLS12::encode to handle TLS 1.3 record encryption if a
     * TLS 1.3 session is established.
     *
     * @param s The application data to encode.
     * @param type The content type of the message.
     * @return The encrypted TLS record.
     */
    std::string encode(std::string &&s, int type = 23);

protected:
    /**
     * @brief Generates the extensions for a ClientHello message.
     * @return A string containing the serialized extensions.
     */
    std::string client_ext();

    /**
     * @brief Generates the extensions for a ServerHello message.
     * @return A string containing the serialized extensions.
     */
    std::string server_ext();

    /**
     * @brief Parses extensions from a received ClientHello message.
     * @param p A pointer to the start of the extensions.
     * @return True if the required extensions are present and valid, false otherwise.
     */
    bool client_ext(unsigned char *p);

    /**
     * @brief Parses extensions from a received ServerHello message.
     * @param p A pointer to the start of the extensions.
     * @return True if a valid key share extension is found, false otherwise.
     */
    bool server_ext(unsigned char *p);

private:
    /**
     * @brief Derives traffic secrets and expands them into AES-GCM keys and IVs.
     *
     * This function is a core part of the TLS 1.3 key schedule. It derives
     * the client and server traffic secrets from the provided salt and handshake
     * messages, then uses these secrets to expand and set the AES-GCM encryption
     * keys and IVs for the session. It also derives the finished keys used for
     * authenticating the handshake.
     *
     * @param salt The salt for HKDF.
     * @param client_label The label for deriving the client traffic secret.
     * @param server_label The label for deriving the server traffic secret.
     * @return An array containing the client and server finished keys.
     */
    std::array<std::vector<uint8_t>, 2>
    set_aes(std::vector<uint8_t> salt, std::string_view client_label, std::string_view server_label);

    /**
     * @brief Checks if the secp256r1 group is in the supported groups extension.
     * @param p Pointer to the extension data.
     * @param len Length of the extension data.
     * @return True if secp256r1 is supported, false otherwise.
     */
    bool supported_group(unsigned char *p, size_t len);

    /**
     * @brief Checks if the uncompressed point format is supported.
     * @param p Pointer to the extension data.
     * @param len Length of the extension data.
     * @return True if uncompressed format is supported, false otherwise.
     */
    bool ec_point_format(unsigned char *p, size_t len);

    /**
     * @brief Processes a single key share entry from the key share extension.
     *
     * It computes the shared secret if a compatible key share is found.
     *
     * @param p Pointer to the key share entry.
     * @return True if a compatible key share was processed, false otherwise.
     */
    bool sub_key_share(unsigned char *p);

    /**
     * @brief Parses the key share extension from a ClientHello.
     * @param p Pointer to the extension data.
     * @param len Length of the extension data.
     * @return True if a compatible key share was found and processed, false otherwise.
     */
    bool key_share(unsigned char *p, size_t len);

    /**
     * @brief Checks if TLS 1.3 is listed in the supported versions extension.
     * @param p Pointer to the extension data.
     * @param len Length of the extension data.
     * @return True if TLS 1.3 is supported, false otherwise.
     */
    bool supported_version(unsigned char *p, size_t len);

    /**
     * @brief Decodes a TLS 1.3 record.
     * @param s The record to decode.
     * @return The decrypted plaintext, or an empty optional on failure.
     */
    std::optional<std::string> decode13(std::string &&s);

    /**
     * @brief Encodes application data into a TLS 1.3 record.
     * @param s The application data to encode.
     * @param type The content type of the data.
     * @return The encrypted TLS 1.3 record.
     */
    std::string encode13(std::string &&s, int type = 23);
};


#endif
