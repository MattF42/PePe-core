// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Version bits for PoW selection
static constexpr int32_t XELISV2_BIT      = 0x8000;
static constexpr int32_t HOOHASHV110_BIT  = 0x4000;

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "util.h"
#include "crypto/xelisv2.h"
#include "uint256.h"

template<typename T1>
void pre_xelis_hash_v2(const T1 pbegin, const T1 pend, uint8_t hash_result[32])
{
    static unsigned char pblank[1];
    xelis_hash_v2((static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]),  hash_result);
    return;
}


template<typename T1>
void pre_hoohash_v110(const T1 pbegin, const T1 pend, uint8_t hash_result[32])
{


    const size_t len = (pend - pbegin) * sizeof(pbegin[0]);

    // We expect BEGIN(nVersion) .. END(nNonce) to be a standard 80-byte header span.
    // Enforcing this prevents accidental consensus changes if header serialization changes.
    assert(len == 80);

    // Hash the serialized block header bytes [nVersion..nNonce]
    hoohashv110(static_cast<const void*>(&pbegin[0]),
                (pend - pbegin) * sizeof(pbegin[0]),
                hash_result);
}


uint256 CBlockHeader::GetPOWHash() const
{
    uint256 PePeHash;

    // Hoohash wins if both bits are present
    if (nVersion & HOOHASHV110_BIT) {
        uint8_t hash_result[32] = {0};

        // Implement this wrapper to hash the header bytes [nVersion..nNonce] and write 32 bytes to hash_result
        pre_hoohash_v110(BEGIN(nVersion), END(nNonce), hash_result);

        std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
    } else if (nVersion & XELISV2_BIT) {
        uint8_t hash_result[32] = {0};
        pre_xelis_hash_v2(BEGIN(nVersion), END(nNonce), hash_result);
        std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
    } else {
        PePeHash = pepe_hash(BEGIN(nVersion), END(nNonce));
    }

    return PePeHash;
}

uint256 CBlockHeader::GetHash() const
{
    uint256 PePeHash;

    // Keep GetHash() consistent with GetPOWHash() (your repo currently treats them the same)
    if (nVersion & HOOHASHV110_BIT) {
        uint8_t hash_result[32] = {0};
        pre_hoohash_v110(BEGIN(nVersion), END(nNonce), hash_result);
        std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
    } else if (nVersion & XELISV2_BIT) {
        uint8_t hash_result[32] = {0};
        pre_xelis_hash_v2(BEGIN(nVersion), END(nNonce), hash_result);
        std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
    } else {
        PePeHash = pepe_hash(BEGIN(nVersion), END(nNonce));
    }

    return PePeHash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}
