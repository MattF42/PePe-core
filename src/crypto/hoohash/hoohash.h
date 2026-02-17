// Copyright (c) 2024 Hoosat Oy
// Copyright (c) 2024 PePe-core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// HoohashV110 Proof of Work Algorithm
// Adapted from https://github.com/HoosatNetwork/hoohash/ commit 9634f11410a2d71be21086e813263fa007fb6810

#ifndef HOOHASH_H
#define HOOHASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Define the size of the hash domain
#define HOOHASH_HASH_SIZE 32

// Compute HoohashV110 on arbitrary data
// data: input data pointer
// len: length of input data in bytes
// output: output buffer (must be at least 32 bytes)
void hoohashv110(const void* data, size_t len, uint8_t output[HOOHASH_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // HOOHASH_H
