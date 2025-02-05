#include "tls/ecdsa.h"

#include <cassert>
#include "tls/mpz.h"

ECDSA::ECDSA(const ECPoint &G, mpz_class n)
    : ECPoint{G} {
    this->n_ = n;
    this->n_bit_ = mpz_sizeinbase(n.get_mpz_t(), 2);
}

mpz_class ECDSA::mod_inv(const mpz_class &z) const {
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), n_.get_mpz_t());
    return r;
}

std::pair<mpz_class, mpz_class> ECDSA::sign(const mpz_class &m, const mpz_class &d) const {
    // Discard last bits if m is too big
    const size_t m_bit = mpz_sizeinbase(m.get_mpz_t(), 2);
    const mpz_class z = m >> std::max(static_cast<int>(m_bit - n_bit_), 0);

    mpz_class k, s, r;
    ECPoint P = *this;
    do {
        do {
            k = random_prime(31);
            P = k * *this; // k * G
            r = P.x_ % n_;
        } while (r == 0);
        s = mod_inv(k) * (z + r * d) % n_;
    } while (s == 0);
    return {r, s};
}

bool ECDSA::verify(const mpz_class &m, const std::pair<mpz_class, mpz_class> &sig, const ECPoint &Q) const {
    auto [r, s] = sig;
    if (r < 1 || r >= n_)
        return false;
    if (s < 1 || s >= n_)
        return false;

    // Discard last bits if m is too big
    const size_t m_bit = mpz_sizeinbase(m.get_mpz_t(), 2);
    const mpz_class z = m >> std::max(static_cast<int>(m_bit - n_bit_), 0);

    const mpz_class inv_s = mod_inv(s);
    const mpz_class u = z * inv_s % n_;
    const mpz_class v = r * inv_s % n_;
    const ECPoint P = u * *this + v * Q;
    if (P.is_identity())
        return false;
    if ((P.x_ - r) % n_ == 0)
        return true;
    return false;
}
