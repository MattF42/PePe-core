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
#include "uint256.h"
#include "crypto/hoohash/hoohash.h"
#include "streams.h"

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

if (len != 80) {
        // Avoid spamming logs in case of repeated malformed input
        static bool logged = false;
        if (!logged) {
            LogPrintf("HoohashV110: unexpected header length %u (expected 80)\n", (unsigned)len);
            logged = true;
        }
        memset(hash_result, 0, 32);
        return;
    }

            // LogPrintf("HoohashV110: will be called\n" );
    // Hash the serialized block header bytes [nVersion..nNonce]
    hoohashv110(static_cast<const void*>(&pbegin[0]),
                (pend - pbegin) * sizeof(pbegin[0]),
                hash_result);
}


uint256 CBlockHeader::GetPOWHash() const
{
    uint256 PePeHash;
// Version bits for PoW selection
static constexpr int32_t XELISV2_BIT      = 0x8000;
static constexpr int32_t HOOHASHV110_BIT  = 0x4000;

    // Hoohash wins if both bits are present
    if (nVersion & HOOHASHV110_BIT) {
        uint8_t hash_result[32] = {0};


        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << *this;

	/*
	LogPrintf("POWDBG hdr80=%s bits=%08x time=%u ver=%08x\n",
			          HexStr(ss.begin(), ss.end()), nBits, nTime, (uint32_t)nVersion);
				  */
        if (ss.size() != 80) {
            LogPrintf("HoohashV110: unexpected serialized header length %u (expected 80)\n", (unsigned)ss.size());
            memset(hash_result, 0, 32);
        } else {
		hoohashv110((const void*)&ss[0], ss.size(), hash_result);
		// LogPrintf("POWDBG hoohash=%s\n", HexStr(hash_result, hash_result + 32));
        }

        return hash_result;	
	// Hash is now correctly reversed at generation time
        // uint256 out;
	// for (int i = 0; i < 32; ++i) out.begin()[i] = hash_result[31 - i];
	// return out;	
        // std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
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
// Version bits for PoW selection
static constexpr int32_t XELISV2_BIT      = 0x8000;
static constexpr int32_t HOOHASHV110_BIT  = 0x4000;

    // Keep GetHash() consistent with GetPOWHash() (your repo currently treats them the same)
    if (nVersion & HOOHASHV110_BIT) {
        uint8_t hash_result[32] = {0};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << *this;

        if (ss.size() != 80) {
            LogPrintf("HoohashV110: unexpected serialized header length %u (expected 80)\n", (unsigned)ss.size());
            memset(hash_result, 0, 32);
        } else {
	    hoohashv110((const void*)&ss[0], ss.size(), hash_result);
        }


        return hash_result;	
	// Hash is now correctly reversed at generation time
        // uint256 out;
        // for (int i = 0; i < 32; ++i) out.begin()[i] = hash_result[31 - i];
        // return out;
        // std::memcpy(&PePeHash, hash_result, sizeof(hash_result));
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
