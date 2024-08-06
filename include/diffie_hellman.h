//
// Created by wtchr on 8/5/2024.
//

#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <gmpxx.h>

/**
 * @brief A struct representing the Diffie-Hellman key exchange protocol.
 */
struct diffie_hellman {
    mpz_class K;
    const mpz_class p, g, x, y;

    /**
     * @brief Constructs a new diffie_hellman object and initializes the parameters.
     */
    diffie_hellman();

    /**
     * @brief Computes and sets the shared secret key from peer's public key.
     * @param pub_key The peer's public key.
     * @return The computed shared secret key.
     */
    mpz_class set_peer_public_key(const mpz_class &pub_key);
};

#endif //DIFFIE_HELLMAN_H
