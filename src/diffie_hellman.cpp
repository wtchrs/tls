//
// Created by wtchr on 8/5/2024.
//

#include "tls/diffie_hellman.h"

#include <cassert>
#include <vector>
#include "tls/mpz.h"

// diffie_hellman

const auto p_value = mpz_class{
        "0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C"
        "75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3"
        "EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE7"
        "6372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FC"
        "BC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"
};

diffie_hellman::diffie_hellman()
    : p{p_value}
    , g{2}
    , x{random_prime(255)}
    , y{powm(g, x, p)} {}

mpz_class diffie_hellman::set_peer_public_key(const mpz_class &pub_key) {
    this->K = powm(pub_key, x, p);
    return K;
}

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

ec_point::ec_point(const mpz_class &x, const mpz_class &y, const ec_field &f)
    : ec_field(f) {
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
    if (r.y == mod)
        return *this; // P + O = P
    if (y == mod)
        return r; // O + P = P
    mpz_class s; // slope
    if (r == *this) {
        if (y == 0)
            return {x, mod, *this}; // Return identity
        s = (3 * x * x + a) * mod_inv(2 * y) % mod;
    } else {
        if (x == r.x)
            return {x, mod, *this}; // Return identity
        s = (r.y - y) * mod_inv(r.x - x) % mod;
    }
    mpz_class x3 = (s * s - x - r.x) % mod;
    mpz_class y3 = (s * (x - x3) - y) % mod;
    if (x3 < 0)
        x3 += mod;
    if (y3 < 0)
        y3 += mod;
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
    for (auto bit : bits) {
        if (bit)
            r = r + x;
        x = x + x; // Double the point
    }
    return r;
}

std::ostream &operator<<(std::ostream &os, const ec_point &r) {
    os << "(" << r.x << ", " << r.y << ")";
    return os;
}
