//
// Created by wtchr on 8/5/2024.
//

#include "mpz.h"

#include <cassert>
#include <iomanip>
#include <random>
#include <vector>

mpz_class nextprime(mpz_class n) {
    mpz_class r;
    mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
    return r;
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod) {
    mpz_class r;
    assert(mod != 0);
    mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return r;
}

mpz_class random_prime(const unsigned b) {
    std::vector<unsigned char> arr(b);
    mpz_class z;
    do {
        std::uniform_int_distribution di{0, 0xff};
        std::random_device rd;
        for (int i = 0; i < b; ++i)
            arr[i] = di(rd);
        z = nextprime(bnd2mpz(arr.begin(), arr.end()));
        std::fill(arr.begin(), arr.end(), 0xff);
        // Retry if z is larger than b bytes
    } while (z > bnd2mpz(arr.begin(), arr.end()));
    return z;
}
