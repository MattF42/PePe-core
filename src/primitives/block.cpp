// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "util.h"
#include "crypto/xelisv2.h"
#include "crypto/hoohash/hoohash.h"
#include "uint256.h"
#include "chainparams.h"

// Block header size constant for PoW hashing (version through nonce)
static const size_t BLOCK_HEADER_SIZE = 80;

template<typename T1>
void pre_xelis_hash_v2(const T1 pbegin, const T1 pend, uint8_t hash_result[32])
{
    static unsigned char pblank[1];
    xelis_hash_v2((static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]),  hash_result);
    return;
}

// Helper function to compute hash using network-specific algorithm
static uint256 ComputeBlockHash(const CBlockHeader* header)
{
    uint256 result;
    
    // Check if we're on regtest or devnet - use Hoohash
    try {
        const CChainParams& params = Params();
        if (params.NetworkIDString() == "regtest" || params.NetworkIDString() == "devnet") {
            uint8_t hash_result[32] = {0};
            const unsigned char* header_begin = (const unsigned char*)header;
            hoohashv110((const void*)header_begin, BLOCK_HEADER_SIZE, hash_result);
            std::memcpy(&result, hash_result, sizeof(hash_result));
            return result;
        }
    } catch (...) {
        // If Params() not available yet (early init), fall through to default
    }
    
    // Mainnet/testnet: use existing PoW selection
    if(header->nVersion & 0x8000) {
        uint8_t hash_result[32] = {0};
        pre_xelis_hash_v2((const unsigned char*)header, 
                         (const unsigned char*)header + BLOCK_HEADER_SIZE, 
                         hash_result);
        std::memcpy(&result, hash_result, sizeof(hash_result));
    } else {
        result = pepe_hash((const unsigned char*)header, 
                          (const unsigned char*)header + BLOCK_HEADER_SIZE);
    }
    return result;
}


uint256 CBlockHeader::GetPOWHash() const
{
    return ComputeBlockHash(this);
}


uint256 CBlockHeader::GetHash() const
{
    return ComputeBlockHash(this);
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
