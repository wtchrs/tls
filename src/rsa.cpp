#include "tls/rsa.h"
#include "tls/mpz.h"

RSA::RSA(const int key_size) {
    // Generate two random primes p and q
    p_ = random_prime(key_size / 2);
    q_ = random_prime(key_size / 2);
    // Compute K = p * q, phi = lcm(p - 1, q - 1), and e such that gcd(e, phi) = 1
    K_ = p_ * q_;
    phi_ = lcm(p_ - 1, q_ - 1);
    for (e_ = 0x10001; gcd(e_, phi_) != 1; e_ = nextprime(e_)) {}
    mpz_invert(d_.get_mpz_t(), e_.get_mpz_t(), phi_.get_mpz_t()); // d = e^-1 mod phi
}

RSA::RSA(const mpz_class &e, const mpz_class &d, const mpz_class &K) {
    this->e_ = e;
    this->d_ = d;
    this->K_ = K;
}

mpz_class RSA::sign(const mpz_class &m) const {
    return decode(m);
}

mpz_class RSA::encode(const mpz_class &m) const {
    // m should be less than K
    return powm(m, e_, K_);
}

mpz_class RSA::decode(const mpz_class &m) const {
    // m should be less than K
    return powm(m, d_, K_);
}
