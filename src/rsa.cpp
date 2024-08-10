//
// Created by wtchr on 8/7/2024.
//

#include "tls/rsa.h"
#include "tls/mpz.h"

rsa_class::rsa_class(const int key_size) {
    // Generate two random primes p and q
    p = random_prime(key_size / 2);
    q = random_prime(key_size / 2);
    // Compute K = p * q, phi = lcm(p - 1, q - 1), and e such that gcd(e, phi) = 1
    K = p * q;
    phi = lcm(p - 1, q - 1);
    for (e = 0x10001; gcd(e, phi) != 1; e = nextprime(e)) {}
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t()); // d = e^-1 mod phi
}

rsa_class::rsa_class(const mpz_class &e, const mpz_class &d, const mpz_class &K) {
    this->e = e;
    this->d = d;
    this->K = K;
}

mpz_class rsa_class::sign(const mpz_class &m) const {
    return decode(m);
}

mpz_class rsa_class::encode(const mpz_class &m) const {
    // m should be less than K
    return powm(m, e, K);
}

mpz_class rsa_class::decode(const mpz_class &m) const {
    // m should be less than K
    return powm(m, d, K);
}
