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

DiffieHellman::DiffieHellman()
    : p_{p_value}
    , g_{2}
    , x_{random_prime(255)}
    , y_{powm(g_, x_, p_)} {}

mpz_class DiffieHellman::set_peer_public_key(const mpz_class &pub_key) {
    this->K_ = powm(pub_key, x_, p_);
    return K_;
}

// ec_field

ECField::ECField(const mpz_class &a, const mpz_class &b, const mpz_class &mod) {
    this->a_ = a;
    this->b_ = b;
    this->mod_ = mod;
}

mpz_class ECField::mod_inv(const mpz_class &z) const {
    mpz_class r;
    mpz_invert(r.get_mpz_t(), z.get_mpz_t(), mod_.get_mpz_t());
    return r;
}

// ec_point

ECPoint::ECPoint(const mpz_class &x, const mpz_class &y, const ECField &f)
    : ECField(f) {
    // Assert the point is an element of the curve.
    if (y != mod_)
        assert((y * y - (x * x * x + a_ * x + b_)) % mod_ == 0);
    this->x_ = x;
    this->y_ = y;
}

bool ECPoint::is_identity() const {
    return y_ == mod_;
}

ECPoint ECPoint::operator+(const ECPoint &r) const {
    // y == mod: O (identity or infinity)
    if (r.y_ == mod_)
        return *this; // P + O = P
    if (y_ == mod_)
        return r; // O + P = P
    mpz_class s; // slope
    if (r == *this) {
        if (y_ == 0)
            return {x_, mod_, *this}; // Return identity
        s = (3 * x_ * x_ + a_) * mod_inv(2 * y_) % mod_;
    } else {
        if (x_ == r.x_)
            return {x_, mod_, *this}; // Return identity
        s = (r.y_ - y_) * mod_inv(r.x_ - x_) % mod_;
    }
    mpz_class x3 = (s * s - x_ - r.x_) % mod_;
    mpz_class y3 = (s * (x_ - x3) - y_) % mod_;
    if (x3 < 0)
        x3 += mod_;
    if (y3 < 0)
        y3 += mod_;
    return {x3, y3, *this};
}

bool ECPoint::operator==(const ECPoint &r) const {
    // Assert the points are on the same curve.
    assert(a_ == r.a_ && b_ == r.b_ && mod_ == r.mod_);
    return x_ == r.x_ && y_ == r.y_;
}

ECPoint operator*(const mpz_class &l, const ECPoint &p) {
    std::vector<bool> bits;
    for (mpz_class n = l; n > 0; n /= 2) {
        bits.push_back(n % 2 == 1);
    }
    ECPoint r = {0, p.mod_, p};
    ECPoint x = p;
    for (auto bit : bits) {
        if (bit)
            r = r + x;
        x = x + x; // Double the point
    }
    return r;
}

std::ostream &operator<<(std::ostream &os, const ECPoint &r) {
    os << "(" << r.x_ << ", " << r.y_ << ")";
    return os;
}
