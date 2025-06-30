#include "core/hkdf.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <gmp.h>
#include <gmpxx.h>
#include <spdlog/spdlog.h>
#include <vector>
#include "core/mpz.h"
#include "core/sha/sha2.h"
#include "util.h"

struct TestCase {
    mpz_class IKM, SALT, INFO, PRK, OKM;
    size_t ikm_len, salt_len, info_len, prk_len, okm_len;
};

// TEST CASES from RFC 5869
// See https://datatracker.ietf.org/doc/html/rfc5869
TestCase cases[] = {
    {mpz_class{"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"}, // 22 octets
     mpz_class{"0x000102030405060708090a0b0c"}, // 13 octets
     mpz_class{"0xf0f1f2f3f4f5f6f7f8f9"}, // 10 octets
     mpz_class{"0x077709362c2e32df0ddc3f0dc47bba63"
               "90b6c73bb50f9c3122ec844ad7c2b3e5"}, // 32 octets
     mpz_class{"0x3cb25f25faacd57a90434f64d0362f2a"
               "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
               "34007208d5b887185865"}, // 42 octets
     22,
     13,
     10,
     32,
     42},
    {mpz_class{"0x000102030405060708090a0b0c0d0e0f"
               "101112131415161718191a1b1c1d1e1f"
               "202122232425262728292a2b2c2d2e2f"
               "303132333435363738393a3b3c3d3e3f"
               "404142434445464748494a4b4c4d4e4f"}, // 80 octets
     mpz_class{"0x606162636465666768696a6b6c6d6e6f"
               "707172737475767778797a7b7c7d7e7f"
               "808182838485868788898a8b8c8d8e8f"
               "909192939495969798999a9b9c9d9e9f"
               "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}, // 80 octets
     mpz_class{"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
               "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
               "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
               "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"}, // 80 octets
     mpz_class{"0x06a6b88c5853361a06104c9ceb35b45c"
               "ef760014904671014a193f40c15fc244"}, // 32 octets
     mpz_class{"0xb11e398dc80327a1c8e7f78c596a4934"
               "4f012eda2d4efad8a050cc4c19afa97c"
               "59045a99cac7827271cb41c65e590e09"
               "da3275600c2f09b8367793a9aca3db71"
               "cc30c58179ec3e87c14c01d5c1f3434f"
               "1d87"}, // 82 octets
     80,
     80,
     80,
     32,
     82},
    {mpz_class{"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"}, // 22 octets
     mpz_class{"0"}, // 0 octets
     mpz_class{"0"}, // 0 octets
     mpz_class{"0x19ef24a32c717b167f33a91d6f648bdf"
               "96596776afdb6377ac434c1c293ccb04"}, // 32 octets
     mpz_class{"0x8da4e775a563c18f715f802a063c5a31"
               "b8a11f5c5ee1879ec3454e5f3c738d2d"
               "9d201395faa4b61a96c8"}, // 42 octets
     22,
     0,
     0,
     32,
     42},
};

TEST_CASE("HKDF Test") {
    for (size_t i = 0; i < sizeof(cases) / sizeof(TestCase); ++i) {
        spdlog::info("HKDF Test {}", i + 1);
        HKDF<SHA256> hkdf_sha256;

        auto &[IKM, SALT, INFO, PRK, OKM, ikm_len, salt_len, info_len, prk_len, okm_len] = cases[i];
        std::vector<uint8_t> ikm(ikm_len);
        std::vector<uint8_t> salt(salt_len);
        std::vector<uint8_t> info(info_len);
        std::vector<uint8_t> prk(prk_len);
        std::vector<uint8_t> okm(okm_len);
        mpz2bnd(IKM, ikm.begin(), ikm.end());
        mpz2bnd(SALT, salt.begin(), salt.end());
        mpz2bnd(INFO, info.begin(), info.end());
        mpz2bnd(PRK, prk.begin(), prk.end());
        mpz2bnd(OKM, okm.begin(), okm.end());

        if (salt.empty()) {
            hkdf_sha256.zero_salt();
        } else {
            hkdf_sha256.salt(&salt[0], salt.size());
        }
        auto prk_result = hkdf_sha256.extract(&ikm[0], ikm.size());

        REQUIRE_MESSAGE(
            std::equal(prk_result.begin(), prk_result.end(), prk.begin()),
            "Failed PRK extracting:\n  expected:\n    " << bytes_to_hex(prk.begin(), prk.end()) << "\n  got:\n    "
                                                        << bytes_to_hex(prk_result.begin(), prk_result.end())
        );

        hkdf_sha256.salt(&prk_result[0], prk_result.size());
        auto okm_result = hkdf_sha256.expand(std::string{info.begin(), info.end()}, okm.size());

        REQUIRE_MESSAGE(
            std::equal(okm_result.begin(), okm_result.end(), okm.begin()),
            "Failed OKM expanding:\n  expected:\n    " << bytes_to_hex(okm.begin(), okm.end()) << "\n  got:\n    "
                                                       << bytes_to_hex(okm_result.begin(), okm_result.end())
        );

        spdlog::info("HKDF Test {} - success", i + 1);
    }
}
