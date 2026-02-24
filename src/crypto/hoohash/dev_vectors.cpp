#include "crypto/hoohash/dev_vectors.h"

#include "crypto/hoohash/hoohash.h"
#include "utilstrencodings.h"
#include "util.h"

#include <array>
#include <cstdint>

// xorshift64* deterministic PRNG (small, stable, no lib deps)
static inline uint64_t xorshift64star(uint64_t& x) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1DULL;
}

void PrintHoohashDevVectors()
{
    // fixed seed => reproducible vectors across runs/builds
    uint64_t s = 0x485F4F4F485F5631ULL; // "H_HOOHV1"-ish

    constexpr int N = 100;

    for (int i = 0; i < N; i++) {
        std::array<unsigned char, 80> hdr{};

        // Fill 80 bytes
        for (size_t j = 0; j < hdr.size(); j++) {
            uint64_t r = xorshift64star(s);
            hdr[j] = static_cast<unsigned char>(r & 0xFF);
        }

        // Force version to select hoohash and match your observed version
        // nVersion = 0x20004000 -> little-endian bytes: 00 40 00 20
        hdr[0] = 0x00;
        hdr[1] = 0x40;
        hdr[2] = 0x00;
        hdr[3] = 0x20;

        uint8_t out[32] = {0};
        hoohashv110(hdr.data(), hdr.size(), out);

        // IMPORTANT: this is the raw hoohash output (same as POWDBG hoohash=...),
        // not the byte-swapped uint256 returned by GetPOWHash().
        LogPrintf("HOOHASHV110_VECTOR i=%d hdr80=%s hoohash=%s\n",
                  i,
                  HexStr(hdr.begin(), hdr.end()),
                  HexStr(out, out + 32));
    }
}
