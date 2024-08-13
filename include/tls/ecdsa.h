//
// Created by wtchr on 8/8/2024.
//

#ifndef ECDSA_H
#define ECDSA_H

#include <gmpxx.h>
#include "diffie_hellman.h"


/**
 * @brief Represents an ECDSA (Elliptic Curve Digital Signature Algorithm) class.
 * This class provides functionalities for signing and verifying messages using ECDSA.
 */
class ecdsa_class : public ec_point {
public:
    /**
     * @brief Constructs an ECDSA object with the given generator point and order.
     * @param G The generator point on the elliptic curve.
     * @param n The order of the generator point.
     */
    ecdsa_class(const ec_point &G, mpz_class n);

    /**
     * @brief Computes the modular inverse of a given value.
     * @param z The value to compute the modular inverse of.
     * @return The modular inverse of z.
     */
    [[nodiscard]]
    mpz_class mod_inv(const mpz_class &z) const;

    /**
     * @brief Signs a message using the private key.
     * @param m The message to sign.
     * @param d The private key.
     * @return A pair containing the signature components (r, s).
     */
    [[nodiscard]]
    std::pair<mpz_class, mpz_class> sign(const mpz_class &m, const mpz_class &d) const;

    /**
     * @brief Verifies a signature for a given message and public key.
     * @param m The message to verify.
     * @param sig The signature to verify, represented as a pair (r, s).
     * @param Q The public key.
     * @return True if the signature is valid, false otherwise.
     */
    [[nodiscard]]
    bool verify(const mpz_class &m, const std::pair<mpz_class, mpz_class> &sig, const ec_point &Q) const;

protected:
    mpz_class n; ///< The order of the generator point.

private:
    size_t n_bit;
};


#endif
