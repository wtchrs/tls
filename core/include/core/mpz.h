#ifndef MPZ_H
#define MPZ_H


#include <algorithm>
#include <gmp.h>
#include <gmpxx.h>
#include <iomanip>
#include <iterator>
#include <sstream>


/**
 * @brief Returns the next prime number greater than n.
 * @param n The starting number.
 * @return The next prime number.
 */
[[nodiscard]]
mpz_class nextprime(const mpz_class &n);

/**
 * @brief Computes (base^exp) % mod.
 * @param base The base number.
 * @param exp The exponent.
 * @param mod The modulus.
 * @return The result of (base^exp) % mod.
 */
[[nodiscard]]
mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod);

/**
 * @brief Generates a random prime number with a specified number of bytes.
 * @param b The number of bytes.
 * @return A random prime number.
 */
[[nodiscard]]
mpz_class random_prime(unsigned b);

/**
 * @brief Converts an mpz_class number to a big endian array.
 * @tparam It Iterator type.
 * @param n The number to convert.
 * @param[out] begin The beginning of the array.
 * @param[out] end The end of the array.
 */
template<typename It>
void mpz2bnd(mpz_class n, It begin, It end) {
    size_t buffer_size_in_bytes = std::distance(begin, end);
    if (buffer_size_in_bytes == 0) {
        return;
    }
    auto num_bytes_n = mpz_sizeinbase(n.get_mpz_t(), 256);
    auto bytes_to_write = std::min(buffer_size_in_bytes, num_bytes_n);

    std::fill(begin, end, 0);

    // Calculate offset for right-alignment.
    if (bytes_to_write < buffer_size_in_bytes) {
        std::advance(begin, buffer_size_in_bytes - bytes_to_write);
    }

    size_t count = 0;
    mpz_export(&(*begin), &count, 1, sizeof(unsigned char), 1, 0, n.get_mpz_t());
}

/**
 * @brief Converts a big endian array to an mpz_class number.
 * @tparam It Iterator type.
 * @param begin The beginning of the array.
 * @param end The end of the array.
 * @return The resulting mpz_class number.
 */
template<typename It>
[[nodiscard]]
mpz_class bnd2mpz(It begin, It end) {
    std::stringstream ss;
    ss << "0x";
    for (It i = begin; i != end; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
    }
    return mpz_class{ss.str()};
}

/**
 * @brief Converts a byte array to a hexadecimal string.
 * @tparam C Container type.
 * @param p The prefix string.
 * @param c The byte array.
 * @return The resulting hexadecimal string.
 */
template<class C>
[[nodiscard]]
std::string hexprint(const char *p, const C &c) {
    std::stringstream ss;
    ss << p << " : 0x";
    for (const unsigned char ch : c)
        ss << std::hex << std::setfill('0') << std::setw(2) << +ch;
    return ss.str();
}


#endif
