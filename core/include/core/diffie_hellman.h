#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H


#include <fmt/core.h>
#include <gmpxx.h>
#include <sstream>


/**
 * @brief A struct representing the Diffie-Hellman Ephemeral.
 */
struct DiffieHellman {
    mpz_class K_;
    const mpz_class p_, g_, x_, y_;

    /**
     * @brief Constructs a new diffie_hellman object and initializes the parameters.
     */
    DiffieHellman();

    /**
     * @brief Computes and sets the shared secret key from peer's public key.
     * @param pub_key The peer's public key.
     * @return The computed shared secret key.
     */
    mpz_class set_peer_public_key(const mpz_class &pub_key);
};


/**
 * @brief Represents an elliptic curve field defined by the equation y^2 = x^3 + ax + b (modulo with the given modulus).
 */
class ECField {
protected:
    mpz_class a_, b_, mod_;

public:
    /**
     * @brief Constructs an elliptic curve field with the given parameters.
     * @param a The coefficient a in the elliptic curve equation.
     * @param b The coefficient b in the elliptic curve equation.
     * @param mod The modulus for the field.
     */
    ECField(const mpz_class &a, const mpz_class &b, const mpz_class &mod);

protected:
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
class ECPoint : ECField {
public:
    mpz_class x_, y_;

    /**
     * @brief Constructs an elliptic curve point with the given coordinates and field.
     * @param x The x-coordinate of the point.
     * @param y The y-coordinate of the point.
     * @param f The elliptic curve field.
     */
    ECPoint(const mpz_class &x, const mpz_class &y, const ECField &f);

    /**
     * @brief Checks if the elliptic curve point is the identity element.
     *
     * The identity element (also known as the point at infinity) is a special point on the elliptic curve
     * that acts as the neutral element for the addition operation. In this implementation, the identity
     * element is represented by a point with the y-coordinate equal to the modulus of the field.
     *
     * @return True if the point is the identity element, false otherwise.
     */
    [[nodiscard]]
    bool is_identity() const;

    /**
     * @brief Adds two elliptic curve points.
     * @param r The point to add.
     * @return The result of the addition.
     */
    ECPoint operator+(const ECPoint &r) const;

    /**
     * @brief Checks if two elliptic curve points are equal.
     * @param r The point to compare with.
     * @return True if the points are equal, false otherwise.
     */
    bool operator==(const ECPoint &r) const;

    /**
     * @brief Multiplies an elliptic curve point by a scalar.
     * @param l The scalar to multiply by.
     * @param p The point to multiply.
     * @return The result of the multiplication.
     */
    friend ECPoint operator*(const mpz_class &l, const ECPoint &p);

    /**
     * @brief Outputs the coordinates of the elliptic curve point to the given output stream.
     * @param os The output stream to write to.
     * @param r The elliptic curve point to output.
     * @return The output stream with the point's coordinates written to it.
     */
    friend std::ostream &operator<<(std::ostream &os, const ECPoint &r);

    friend struct fmt::formatter<ECPoint>;
};


template<>
struct fmt::formatter<ECPoint> {
    template<typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template<typename FormatContext>
    auto format(const ECPoint &value, FormatContext &ctx) const {
        std::ostringstream oss;
        oss << value;
        return fmt::format_to(ctx.out(), "{}", oss.str());
    }
};


#endif
