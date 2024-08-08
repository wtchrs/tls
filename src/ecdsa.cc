//
// Created by wtchr on 8/8/2024.
//

#include "ecdsa.h"

#include <cassert>
#include <vector>
#include "mpz.h"

// ec_field

ec_field::ec_field(const mpz_class &a, const mpz_class &b, const mpz_class &mod) {
    this->a = a;
    this->b = b;
    this->mod = mod;
}

mpz_class ec_field::mod_inv(const mpz_class &z) const {
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod.get_mpz_t());
    return r;
}

// ec_point

ec_point::ec_point(const mpz_class &x, const mpz_class &y, const ec_field &f) : ec_field(f) {
    // Assert the point is an element of the curve.
    if (y != mod)
        assert((y * y - (x * x * x + a * x + b)) % mod == 0);
    this->x = x;
    this->y = y;
}

bool ec_point::is_identity() const {
    return y == mod;
}

ec_point ec_point::operator+(const ec_point &r) const {
    // y == mod: O (identity or infinity)
    if (r.y == mod) return *this; // P + O = P
    if (y == mod) return r; // O + P = P
    mpz_class s; // slope
    if (r == *this) {
        if (y == 0) return {x, mod, *this}; // Return identity
        s = (3 * x * x + a) * mod_inv(2 * y) % mod;
    } else {
        if (x == r.x) return {x, mod, *this}; // Return identity
        s = (r.y - y) * mod_inv(r.x - x) % mod;
    }
    mpz_class x3 = (s * s - x - r.x) % mod;
    mpz_class y3 = (s * (x - x3) - y) % mod;
    if (x3 < 0) x3 += mod;
    if (y3 < 0) y3 += mod;
    return {x3, y3, *this};
}

bool ec_point::operator==(const ec_point &r) const {
    // Assert the points are on the same curve.
    assert(a == r.a && b == r.b && mod == r.mod);
    return x == r.x && y == r.y;
}

ec_point operator*(const mpz_class &l, const ec_point &p) {
    std::vector<bool> bits;
    for (mpz_class n = l; n > 0; n /= 2) {
        bits.push_back(n % 2 == 1);
    }
    ec_point r = {0, p.mod, p};
    ec_point x = p;
    for (auto bit: bits) {
        if (bit) r = r + x;
        x = x + x; // Double the point
    }
    return r;
}

std::ostream &operator<<(std::ostream &os, const ec_point &r) {
    os << "(" << r.x << ", " << r.y << ")";
    return os;
}

// ecdsa

ecdsa_class::ecdsa_class(const ec_point &G, mpz_class n) : ec_point{G} {
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

bool ecdsa_class::verify(const mpz_class &m, const std::pair<mpz_class, mpz_class> &sig, const ec_point& Q) const {
    auto [r, s] = sig;
    if (r < 1 || r >= n) return false;
    if (s < 1 || s >= n) return false;

    // Discard last bits if m is too big
    const size_t m_bit = mpz_sizeinbase(m.get_mpz_t(), 2);
    const mpz_class z = m >> std::max(static_cast<int>(m_bit - n_bit), 0);

    const mpz_class inv_s = mod_inv(s);
    const mpz_class u = z * inv_s % n;
    const mpz_class v = r * inv_s % n;
    const ec_point P = u * *this + v * Q;
    if (P.is_identity()) return false;
    if ((P.x - r) % n == 0) return true;
    return false;
}
