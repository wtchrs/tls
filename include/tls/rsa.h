#ifndef RSA_H
#define RSA_H


#include <gmpxx.h>


/**
 * @brief A class that implements RSA encryption and decryption.
 */
class RSA {
public:
    mpz_class K_, e_;

protected:
    mpz_class p_, q_, d_, phi_;

public:
    /**
     * @brief Constructs an RSA object with a specified key size.
     *
     * This constructor generates two random prime numbers, computes the modulus,
     * the totient, and the public and private exponents.
     *
     * @param key_size The size of the RSA key in bits.
     */
    explicit RSA(int key_size);

    /**
     * @brief Constructs an RSA object with provided public and private keys.
     * @param e The public exponent.
     * @param d The private exponent.
     * @param K The modulus.
     */
    RSA(const mpz_class &e, const mpz_class &d, const mpz_class &K);

    /**
     * @brief Signs a message by decoding it with the private key.
     * @param m The message to be signed.
     * @return The signed message.
     */
    [[nodiscard]]
    mpz_class sign(const mpz_class &m) const;

    /**
     * @brief Encodes a message using the public key.
     * @param m The message to be encoded.
     * @return The encoded message.
     */
    [[nodiscard]]
    mpz_class encode(const mpz_class &m) const;

    /**
     * @brief Decodes a message using the private key.
     * @param m The message to be decoded.
     * @return The decoded message.
     */
    [[nodiscard]]
    mpz_class decode(const mpz_class &m) const;
};


#endif
