#include "tls/prf.h"
#include <catch2/catch_test_macros.hpp>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include "tls/mpz.h"
#include "tls/sha/sha1.h"

TEST_CASE("PRF test") {
    PRF<SHA1> prf;
    unsigned char seed[100], secret[100];
    std::vector<std::vector<unsigned char>> vv;
    mpz_class z1{"0x3a64b675191395ba19842ad7d14c2d798fe9e2dab6b9ebcdfab50ec68a862691effbff693bc68643a6463c71b322c9d7cb3"
                 "e0b29c15dbee6d11d42667a014183"};
    mpz_class z2{"0xc5048557a1a02314403003ee56326aaf33bc3c10fd7f00007280a784ca5500006b9ccfad52e06aedb01f4eab6c2caaa6"};
    mpz_class expected{"0x3b6b817ecb6fd456d4989b24832ecdad44a8349bc0c7551d84fb2da638909846fbb1f984f4b35b6ff7103e687493b"
                       "3e7b7296096fcb3ee8358082da129eaceb4766e1f20cdf25901"};
    int sz1 = (mpz_sizeinbase(z1.get_mpz_t(), 16) + 1) / 2;
    int sz2 = (mpz_sizeinbase(z2.get_mpz_t(), 16) + 1) / 2;
    mpz2bnd(z1, seed, seed + sz1);
    mpz2bnd(z2, secret, secret + sz2);
    prf.label("master secret");
    prf.seed(seed, seed + sz1);
    prf.secret(secret, secret + sz2);
    auto a = prf.get_n_bytes(72);
    REQUIRE(expected == bnd2mpz(a.cbegin(), a.cend()));
}
