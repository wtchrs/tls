#ifndef CORE_UTILS_H
#define CORE_UTILS_H


#include <string>
#include <type_traits>

/**
 * @brief Concept for types that can be safely serialized as raw byte sequences.
 *
 * This concept ensures that a type is trivially copyable and has a standard layout,
 * making it suitable for reinterpretation as a raw byte buffer.
 *
 * @note This concept does NOT guarantee that the type has no padding between members.
 *       Take care if you require a truly packed (no-padding) representation.
 */
template<typename T>
concept ByteSerializable = std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>;

/**
 * @brief Translate any struct to a byte array represented as a string.
 *
 * This function performs raw memory copy of the struct into a `std::string`,
 * in order to treat the struct as a contiguous sequence of bytes.
 *
 * @tparam T Type of struct. Must be trivially copyable and standard-layout.
 * @param t Struct instance to convert.
 * @return a std::string containing the raw byte representation of the struct.
 *
 * @note This function assumes the memory layout of the struct is suitable for
 *       direct reinterpretation. Avoid using with non-POD types or types with
 *       pointers or virtual methods.
 */
template<ByteSerializable T>
std::string struct2str(const T &t) {
    return std::string{reinterpret_cast<const char *>(&t), sizeof(t)};
}


#endif
