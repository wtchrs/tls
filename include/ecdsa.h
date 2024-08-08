//
// Created by wtchr on 8/8/2024.
//

#ifndef ECDSA_H
#define ECDSA_H

#include <gmpxx.h>


/**
 * @brief Represents an elliptic curve field defined by the equation y^2 = x^3 + ax + b (mod mod).
 */
class ec_field {
public:
    /**
     * @brief Constructs an elliptic curve field with the given parameters.
     * @param a The coefficient a in the elliptic curve equation.
     * @param b The coefficient b in the elliptic curve equation.
     * @param mod The modulus for the field.
     */
    ec_field(const mpz_class &a, const mpz_class &b, const mpz_class &mod);

protected:
    mpz_class a, b, mod;

    /**
     * @brief Computes the modular inverse of a given value.
     * @param z The value to compute the modular inverse of.
     * @return The modular inverse of z.
     */
    [[nodiscard]]
    mpz_class mod_inv(const mpz_class &z) const;
};


/**
 * @brief Represents a point on an elliptic curve.
 */
struct ec_point : ec_field {
    mpz_class x, y;

    /**
     * @brief Constructs an elliptic curve point with the given coordinates and field.
     * @param x The x-coordinate of the point.
     * @param y The y-coordinate of the point.
     * @param f The elliptic curve field.
     */
    ec_point(const mpz_class &x, const mpz_class &y, const ec_field &f);

    [[nodiscard]]
    bool is_identity() const;

    /**
     * @brief Adds two elliptic curve points.
     * @param r The point to add.
     * @return The result of the addition.
     */
    ec_point operator+(const ec_point &r) const;

    /**
     * @brief Checks if two elliptic curve points are equal.
     * @param r The point to compare with.
     * @return True if the points are equal, false otherwise.
     */
    bool operator==(const ec_point &r) const;

    /**
     * @brief Multiplies an elliptic curve point by a scalar.
     * @param l The scalar to multiply by.
     * @param p The point to multiply.
     * @return The result of the multiplication.
     */
    friend ec_point operator*(const mpz_class &l, const ec_point &p);

    /**
     * @brief Outputs the coordinates of the elliptic curve point to the given output stream.
     * @param os The output stream to write to.
     * @param r The elliptic curve point to output.
     * @return The output stream with the point's coordinates written to it.
     */
    friend std::ostream &operator<<(std::ostream &os, const ec_point &r);
};


/**
 * @brief Represents an ECDSA (Elliptic Curve Digital Signature Algorithm) class.
 * This class provides functionalities for signing and verifying messages using ECDSA.
 */
class ecdsa_class : public ec_point {
public:
    /**
     * @brief Constructs an ECDSA object with the given generator point and order.
     * @param G The generator point on the elliptic curve.
     * @param n The order of the generator point.
     */
    ecdsa_class(const ec_point &G, mpz_class n);

    /**
     * @brief Computes the modular inverse of a given value.
     * @param z The value to compute the modular inverse of.
     * @return The modular inverse of z.
     */
    [[nodiscard]]
    mpz_class mod_inv(const mpz_class &z) const;

    /**
     * @brief Signs a message using the private key.
     * @param m The message to sign.
     * @param d The private key.
     * @return A pair containing the signature components (r, s).
     */
    [[nodiscard]]
    std::pair<mpz_class, mpz_class> sign(const mpz_class &m, const mpz_class &d) const;

    /**
     * @brief Verifies a signature for a given message and public key.
     * @param m The message to verify.
     * @param sig The signature to verify, represented as a pair (r, s).
     * @param Q The public key.
     * @return True if the signature is valid, false otherwise.
     */
    [[nodiscard]]
    bool verify(const mpz_class &m, const std::pair<mpz_class, mpz_class> &sig, const ec_point &Q) const;

protected:
    mpz_class n; ///< The order of the generator point.

private:
    size_t n_bit;
};


#endif //ECDSA_H
