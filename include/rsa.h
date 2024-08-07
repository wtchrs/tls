//
// Created by wtchr on 8/7/2024.
//

#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>


class rsa_class {
public:
    mpz_class K, e;

    rsa_class(int key_size);

    rsa_class(const mpz_class& e, const mpz_class& d, const mpz_class& K);

    mpz_class sign(const mpz_class& m) const;

    mpz_class encode(const mpz_class& m) const;

    mpz_class decode(const mpz_class& m) const;

protected:
    mpz_class p, q, d, phi;
};


#endif //RSA_H
