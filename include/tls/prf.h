#ifndef PRF_H
#define PRF_H


#include <algorithm>
#include "tls/hmac.h"


/**
 * @brief Pseudo-Random Function (PRF) implementation for TLS protocol
 *
 * This class implements the PRF function as defined in TLS specifications.
 * It generates a pseudo-random byte sequence using HMAC with a specified
 * hash function, secret, label, and seed.
 *
 * @tparam Hash The hash function to be used (must satisfy HashFunction concept)
 */
template<HashFunction Hash>
class PRF {
private:
    HMAC<Hash> hmac_; ///< HMAC object
    std::vector<unsigned char> label_, seed_; ///< Label and seed data

public:
    /**
     * @brief Sets the secret key for the PRF
     *
     * @tparam IT Iterator type for the input range
     * @param begin Iterator to the start of the secret key
     * @param end Iterator to the end of the secret key
     */
    template<typename IT>
    void secret(const IT begin, const IT end);

    /**
     * @brief Sets the label string for the PRF
     *
     * The label is a null-terminated string that is used as part of
     * the input to the PRF calculation.
     *
     * @param p Pointer to null-terminated label string
     */
    void label(const char *p);

    /**
     * @brief Sets the seed data for the PRF
     *
     * @tparam IT Iterator type for the input range
     * @param begin Iterator to the start of the seed data
     * @param end Iterator to the end of the seed data
     */
    template<typename IT>
    void seed(const IT begin, const IT end);

    /**
     * @brief Generates n pseudo-random bytes
     *
     * Implements the TLS PRF algorithm to generate the requested number
     * of pseudo-random bytes using the configured secret, label, and seed.
     *
     * @param n Number of bytes to generate
     * @return std::vector<unsigned char> Vector containing n pseudo-random bytes
     */
    std::vector<unsigned char> get_n_bytes(size_t n);
};


template<HashFunction Hash>
template<typename IT>
void PRF<Hash>::secret(const IT begin, const IT end) {
    hmac_.key(begin, end);
}

template<HashFunction Hash>
void PRF<Hash>::label(const char *p) {
    label_.clear();
    while (*p) {
        label_.push_back(*p++);
    }
}

template<HashFunction Hash>
template<typename IT>
void PRF<Hash>::seed(const IT begin, const IT end) {
    seed_.clear();
    for (IT it = begin; it != end; ++it) {
        seed_.push_back(*it);
    }
}

template<HashFunction Hash>
std::vector<unsigned char> PRF<Hash>::get_n_bytes(size_t n) {
    // seed = A(0) = label_ + seed_
    auto seed = label_;
    seed.insert(seed.end(), seed_.cbegin(), seed_.cend());
    std::vector<unsigned char> r, v;
    /* std::array<unsigned char, Hash::output_size> */ auto A = hmac_.hash(seed.cbegin(), seed.cend()); // A(1)
    v.resize(A.size()); // A(i) will be copied into this new space.
    v.insert(v.end(), seed.cbegin(), seed.cend());
    for (; r.size() < n; /* Calculate A(i) */ A = hmac_.hash(A.cbegin(), A.cend())) {
        std::copy(A.cbegin(), A.cend(), v.begin());
        auto next_block = hmac_.hash(v.cbegin(), v.cend());
        r.insert(r.end(), next_block.cbegin(), next_block.cend());
    }
    r.resize(n);
    return r;
}


#endif
