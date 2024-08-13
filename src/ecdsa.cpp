//
// Created by wtchr on 8/8/2024.
//

#include "tls/ecdsa.h"

#include <cassert>
#include <vector>
#include "tls/mpz.h"

ecdsa_class::ecdsa_class(const ec_point &G, mpz_class n)
    : ec_point{G} {
    this->n = n;
    this->n_bit = mpz_sizeinbase(n.get_mpz_t(), 2);
}

mpz_class ecdsa_class::mod_inv(const mpz_class &z) const {
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), n.get_mpz_t());
    return r;
}

std::pair<mpz_class, mpz_class> ecdsa_class::sign(const mpz_class &m, const mpz_class &d) const {
    // Discard last bits if m is too big
    const size_t m_bit = mpz_sizeinbase(m.get_mpz_t(), 2);
    const mpz_class z = m >> std::max(static_cast<int>(m_bit - n_bit), 0);

    mpz_class k, s, r;
    ec_point P = *this;
    do {
        do {
            k = random_prime(31);
            P = k * *this; // k * G
            r = P.x % n;
        } while (r == 0);
        s = mod_inv(k) * (z + r * d) % n;
    } while (s == 0);
    return {r, s};
}

bool ecdsa_class::verify(const mpz_class &m, const std::pair<mpz_class, mpz_class> &sig, const ec_point &Q) const {
    auto [r, s] = sig;
    if (r < 1 || r >= n)
        return false;
    if (s < 1 || s >= n)
        return false;

    // Discard last bits if m is too big
    const size_t m_bit = mpz_sizeinbase(m.get_mpz_t(), 2);
    const mpz_class z = m >> std::max(static_cast<int>(m_bit - n_bit), 0);

    const mpz_class inv_s = mod_inv(s);
    const mpz_class u = z * inv_s % n;
    const mpz_class v = r * inv_s % n;
    const ec_point P = u * *this + v * Q;
    if (P.is_identity())
        return false;
    if ((P.x - r) % n == 0)
        return true;
    return false;
}
