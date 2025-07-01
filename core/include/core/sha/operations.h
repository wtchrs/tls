/** Define the operations used in the SHA-2 hash computation. */

#ifndef CORE_SHA_OPERATIONS_H
#define CORE_SHA_OPERATIONS_H


#include <cstdint>

uint32_t rotr(const uint32_t x, const int n);
uint64_t rotr(const uint64_t x, const int n);

uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z);
uint64_t ch(const uint64_t x, const uint64_t y, const uint64_t z);

uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z);
uint64_t maj(const uint64_t x, const uint64_t y, const uint64_t z);

uint32_t bsig0(const uint32_t x);
uint64_t bsig0(const uint64_t x);

uint32_t bsig1(const uint32_t x);
uint64_t bsig1(const uint64_t x);

uint32_t ssig0(const uint32_t x);
uint64_t ssig0(const uint64_t x);

uint32_t ssig1(const uint32_t x);
uint64_t ssig1(const uint64_t x);


#endif
