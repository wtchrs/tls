//
// Created by wtchr on 8/5/2024.
//

#ifndef MPZ_H
#define MPZ_H

#include <gmpxx.h>
#include <iomanip>
#include <sstream>


/**
 * @brief Returns the next prime number greater than n.
 * @param n The starting number.
 * @return The next prime number.
 */
mpz_class nextprime(const mpz_class &n);

/**
 * @brief Computes (base^exp) % mod.
 * @param base The base number.
 * @param exp The exponent.
 * @param mod The modulus.
 * @return The result of (base^exp) % mod.
 */
mpz_class powm(const mpz_class &base, const mpz_class &exp, const mpz_class &mod);

/**
 * @brief Generates a random prime number with a specified number of bytes.
 * @param b The number of bytes.
 * @return A random prime number.
 */
mpz_class random_prime(unsigned b);

/**
 * @brief Converts an mpz_class number to a big endian array.
 * @tparam It Iterator type.
 * @param n The number to convert.
 * @param begin The beginning of the array.
 * @param end The end of the array.
 */
template<typename It>
void mpz2bnd(mpz_class n, It begin, It end) {
    for (It i = end; i != begin; n /= 0x100) {
        *--i = mpz_class{n % 0x100}.get_ui();
    }
}

/**
 * @brief Converts a big endian array to an mpz_class number.
 * @tparam It Iterator type.
 * @param begin The beginning of the array.
 * @param end The end of the array.
 * @return The resulting mpz_class number.
 */
template<typename It>
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
std::string hexprint(const char *p, const C &c) {
    std::stringstream ss;
    ss << p << " : 0x";
    for (const unsigned char ch: c)
        ss << std::hex << std::setfill('0') << std::setw(2) << +ch;
    return ss.str();
}


#endif //MPZ_H
