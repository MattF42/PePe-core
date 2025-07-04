// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"
#include "messagesigner.h"
#include "net_processing.h"
#include "spork.h"

#include <boost/lexical_cast.hpp>

class CSporkMessage;
class CSporkManager;

CSporkManager sporkManager;

std::map<uint256, CSporkMessage> mapSporks;

void CSporkManager::ProcessSpork(CNode* pfrom, std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all PEPEPOW specific functionality

    if (strCommand == NetMsgType::SPORK) {

        CSporkMessage spork;
        vRecv >> spork;

        uint256 hash = spork.GetHash();

        std::string strLogMsg;
        {
            LOCK(cs_main);
            pfrom->setAskFor.erase(hash);
            if(!chainActive.Tip()) return;
            // Log both int and string value, if present
            strLogMsg = strprintf("SPORK -- hash: %s id: %d value: %10d string: \"%s\" bestHeight: %d peer=%d", hash.ToString(), spork.nSporkID, spork.nValue, spork.sValue, chainActive.Height(), pfrom->id);
        }

        if(mapSporksActive.count(spork.nSporkID)) {
            if (mapSporksActive[spork.nSporkID].nTimeSigned >= spork.nTimeSigned) {
                LogPrint("spork", "%s seen\n", strLogMsg);
                return;
            } else {
                LogPrintf("%s updated\n", strLogMsg);
            }
        } else {
            LogPrintf("%s new\n", strLogMsg);
        }

        if(!spork.CheckSignature()) {
            LogPrintf("CSporkManager::ProcessSpork -- invalid signature\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        mapSporks[hash] = spork;
        mapSporksActive[spork.nSporkID] = spork;
        spork.Relay(connman);

        //does a task if needed
        ExecuteSpork(spork.nSporkID, spork.nValue);

    } else if (strCommand == NetMsgType::GETSPORKS) {

        std::map<int, CSporkMessage>::iterator it = mapSporksActive.begin();

        while(it != mapSporksActive.end()) {
            connman.PushMessage(pfrom, NetMsgType::SPORK, it->second);
            it++;
        }
    }

}

void CSporkManager::ExecuteSpork(int nSporkID, int nValue)
{
    //correct fork via spork technology
    if(nSporkID == SPORK_12_RECONSIDER_BLOCKS && nValue > 0) {
        // allow to reprocess 24h of blocks max, which should be enough to resolve any issues
        int64_t nMaxBlocks = 576;
        // this potentially can be a heavy operation, so only allow this to be executed once per 10 minutes
        int64_t nTimeout = 10 * 60;

        static int64_t nTimeExecuted = 0; // i.e. it was never executed before

        if(GetTime() - nTimeExecuted < nTimeout) {
            LogPrint("spork", "CSporkManager::ExecuteSpork -- ERROR: Trying to reconsider blocks, too soon - %d/%d\n", GetTime() - nTimeExecuted, nTimeout);
            return;
        }

        if(nValue > nMaxBlocks) {
            LogPrintf("CSporkManager::ExecuteSpork -- ERROR: Trying to reconsider too many blocks %d/%d\n", nValue, nMaxBlocks);
            return;
        }


        LogPrintf("CSporkManager::ExecuteSpork -- Reconsider Last %d Blocks\n", nValue);

        ReprocessBlocks(nValue);
        nTimeExecuted = GetTime();
    }
}

// Integer spork update (legacy)
bool CSporkManager::UpdateSpork(int nSporkID, int64_t nValue, CConnman& connman)
{
    CSporkMessage spork = CSporkMessage(nSporkID, nValue, GetAdjustedTime());

    if(spork.Sign(strMasterPrivKey)) {
        spork.Relay(connman);
        mapSporks[spork.GetHash()] = spork;
        mapSporksActive[nSporkID] = spork;
        return true;
    }

    return false;
}

// String spork update (new)
bool CSporkManager::UpdateSpork(int nSporkID, const std::string& sValue, CConnman& connman)
{
    CSporkMessage spork(nSporkID, sValue, GetAdjustedTime());

    if(spork.Sign(strMasterPrivKey)) {
        spork.Relay(connman);
        mapSporks[spork.GetHash()] = spork;
        mapSporksActive[nSporkID] = spork;
        return true;
    }

    return false;
}

// Integer spork value (legacy)
bool CSporkManager::IsSporkActive(int nSporkID)
{
    int64_t r = -1;

    if(mapSporksActive.count(nSporkID)){
        r = mapSporksActive[nSporkID].nValue;
    } else {
        switch (nSporkID) {
            case SPORK_2_INSTANTSEND_ENABLED:               r = SPORK_2_INSTANTSEND_ENABLED_DEFAULT; break;
            case SPORK_3_INSTANTSEND_BLOCK_FILTERING:       r = SPORK_3_INSTANTSEND_BLOCK_FILTERING_DEFAULT; break;
            case SPORK_5_INSTANTSEND_MAX_VALUE:             r = SPORK_5_INSTANTSEND_MAX_VALUE_DEFAULT; break;
            case SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT:    r = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT_DEFAULT; break;
            case SPORK_9_SUPERBLOCKS_ENABLED:               r = SPORK_9_SUPERBLOCKS_ENABLED_DEFAULT; break;
            case SPORK_10_MASTERNODE_PAY_UPDATED_NODES:     r = SPORK_10_MASTERNODE_PAY_UPDATED_NODES_DEFAULT; break;
            case SPORK_12_RECONSIDER_BLOCKS:                r = SPORK_12_RECONSIDER_BLOCKS_DEFAULT; break;
            case SPORK_13_OLD_SUPERBLOCK_FLAG:              r = SPORK_13_OLD_SUPERBLOCK_FLAG_DEFAULT; break;
            case SPORK_14_REQUIRE_SENTINEL_FLAG:            r = SPORK_14_REQUIRE_SENTINEL_FLAG_DEFAULT; break;
            case SPORK_15_REQUIRE_FOUNDATION_FEE:           r = SPORK_15_REQUIRE_FOUNDATION_FEE_DEFAULT; break;
            case SPORK_16_XELISV2:		            r = SPORK_16_XELISV2_DEFAULT; break;
            case SPORK_17_TIERED_MN:		            r = SPORK_17_TIERED_MN_DEFAULT;  break;
            case SPORK_18_AUTOSPORK:		            r = SPORK_18_AUTOSPORK_DEFAULT;  break;
            case SPORK_21_FREEZE_BLACKLIST:	            r = SPORK_21_FREEZE_BLACKLIST_DEFAULT;  break;
            default:
                LogPrint("spork", "CSporkManager::IsSporkActive -- Unknown Spork ID %d\n", nSporkID);
                r = 4070908800ULL; // 2099-1-1 i.e. off by default
                break;
        }
    }

    return r < GetAdjustedTime();
}

// Integer spork value (legacy)
int64_t CSporkManager::GetSporkValue(int nSporkID)
{
    if (mapSporksActive.count(nSporkID))
        return mapSporksActive[nSporkID].nValue;

    switch (nSporkID) {
        case SPORK_2_INSTANTSEND_ENABLED:               return SPORK_2_INSTANTSEND_ENABLED_DEFAULT;
        case SPORK_3_INSTANTSEND_BLOCK_FILTERING:       return SPORK_3_INSTANTSEND_BLOCK_FILTERING_DEFAULT;
        case SPORK_5_INSTANTSEND_MAX_VALUE:             return SPORK_5_INSTANTSEND_MAX_VALUE_DEFAULT;
        case SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT:    return SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT_DEFAULT;
        case SPORK_9_SUPERBLOCKS_ENABLED:               return SPORK_9_SUPERBLOCKS_ENABLED_DEFAULT;
        case SPORK_10_MASTERNODE_PAY_UPDATED_NODES:     return SPORK_10_MASTERNODE_PAY_UPDATED_NODES_DEFAULT;
        case SPORK_12_RECONSIDER_BLOCKS:                return SPORK_12_RECONSIDER_BLOCKS_DEFAULT;
        case SPORK_13_OLD_SUPERBLOCK_FLAG:              return SPORK_13_OLD_SUPERBLOCK_FLAG_DEFAULT;
        case SPORK_14_REQUIRE_SENTINEL_FLAG:            return SPORK_14_REQUIRE_SENTINEL_FLAG_DEFAULT;
        case SPORK_15_REQUIRE_FOUNDATION_FEE:           return SPORK_15_REQUIRE_FOUNDATION_FEE_DEFAULT; 
        case SPORK_16_XELISV2: 			        return SPORK_16_XELISV2_DEFAULT;
        case SPORK_17_TIERED_MN: 		        return SPORK_17_TIERED_MN_DEFAULT;
        case SPORK_18_AUTOSPORK: 		        return SPORK_18_AUTOSPORK_DEFAULT;
        case SPORK_21_FREEZE_BLACKLIST:		        return SPORK_21_FREEZE_BLACKLIST_DEFAULT;
        default:
            LogPrint("spork", "CSporkManager::GetSporkValue -- Unknown Spork ID %d\n", nSporkID);
            return -1;
    }

}

// String spork value (returns true if found and non-empty)
bool CSporkManager::GetSporkStringValue(int nSporkID, std::string& sValueRet)
{
    if (mapSporksActive.count(nSporkID)) {
        sValueRet = mapSporksActive[nSporkID].sValue;
        return !sValueRet.empty();
    }
    sValueRet.clear();
    return false;
}

// Unified getter for string/int (string preferred)
bool CSporkManager::GetSporkValueString(int nSporkID, std::string& sRet)
{
    if (mapSporksActive.count(nSporkID)) {
        const CSporkMessage& spork = mapSporksActive[nSporkID];
        if (!spork.sValue.empty()) {
            sRet = spork.sValue;
            return true;
        }
        sRet = std::to_string(spork.nValue);
        return true;
    }
    sRet.clear();
    return false;
}

int CSporkManager::GetSporkIDByName(std::string strName)
{
    if (strName == "SPORK_2_INSTANTSEND_ENABLED")               return SPORK_2_INSTANTSEND_ENABLED;
    if (strName == "SPORK_3_INSTANTSEND_BLOCK_FILTERING")       return SPORK_3_INSTANTSEND_BLOCK_FILTERING;
    if (strName == "SPORK_5_INSTANTSEND_MAX_VALUE")             return SPORK_5_INSTANTSEND_MAX_VALUE;
    if (strName == "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT")    return SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
    if (strName == "SPORK_9_SUPERBLOCKS_ENABLED")               return SPORK_9_SUPERBLOCKS_ENABLED;
    if (strName == "SPORK_10_MASTERNODE_PAY_UPDATED_NODES")     return SPORK_10_MASTERNODE_PAY_UPDATED_NODES;
    if (strName == "SPORK_12_RECONSIDER_BLOCKS")                return SPORK_12_RECONSIDER_BLOCKS;
    if (strName == "SPORK_13_OLD_SUPERBLOCK_FLAG")              return SPORK_13_OLD_SUPERBLOCK_FLAG;
    if (strName == "SPORK_14_REQUIRE_SENTINEL_FLAG")            return SPORK_14_REQUIRE_SENTINEL_FLAG;
    if (strName == "SPORK_15_REQUIRE_FOUNDATION_FEE")           return SPORK_15_REQUIRE_FOUNDATION_FEE;
    if (strName == "SPORK_16_XELISV2") 			        return SPORK_16_XELISV2;
    if (strName == "SPORK_17_TIERED_MN") 		        return SPORK_17_TIERED_MN;
    if (strName == "SPORK_18_AUTOSPORK") 		        return SPORK_18_AUTOSPORK;
    if (strName == "SPORK_21_FREEZE_BLACKLIST")		        return SPORK_21_FREEZE_BLACKLIST;

    LogPrint("spork", "CSporkManager::GetSporkIDByName -- Unknown Spork name '%s'\n", strName);
    return -1;
}

std::string CSporkManager::GetSporkNameByID(int nSporkID)
{
    switch (nSporkID) {
        case SPORK_2_INSTANTSEND_ENABLED:               return "SPORK_2_INSTANTSEND_ENABLED";
        case SPORK_3_INSTANTSEND_BLOCK_FILTERING:       return "SPORK_3_INSTANTSEND_BLOCK_FILTERING";
        case SPORK_5_INSTANTSEND_MAX_VALUE:             return "SPORK_5_INSTANTSEND_MAX_VALUE";
        case SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT:    return "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT";
        case SPORK_9_SUPERBLOCKS_ENABLED:               return "SPORK_9_SUPERBLOCKS_ENABLED";
        case SPORK_10_MASTERNODE_PAY_UPDATED_NODES:     return "SPORK_10_MASTERNODE_PAY_UPDATED_NODES";
        case SPORK_12_RECONSIDER_BLOCKS:                return "SPORK_12_RECONSIDER_BLOCKS";
        case SPORK_13_OLD_SUPERBLOCK_FLAG:              return "SPORK_13_OLD_SUPERBLOCK_FLAG";
        case SPORK_14_REQUIRE_SENTINEL_FLAG:            return "SPORK_14_REQUIRE_SENTINEL_FLAG";
        case SPORK_15_REQUIRE_FOUNDATION_FEE:           return "SPORK_15_REQUIRE_FOUNDATION_FEE";
        case SPORK_16_XELISV2: 			        return "SPORK_16_XELISV2";
        case SPORK_17_TIERED_MN: 		        return "SPORK_17_TIERED_MN";
        case SPORK_18_AUTOSPORK: 		        return "SPORK_18_AUTOSPORK";
        case SPORK_21_FREEZE_BLACKLIST:		        return "SPORK_21_FREEZE_BLACKLIST";
        default:
            LogPrint("spork", "CSporkManager::GetSporkNameByID -- Unknown Spork ID %d\n", nSporkID);
            return "Unknown";
    }
}

bool CSporkManager::SetPrivKey(std::string strPrivKey)
{
    CSporkMessage spork;

    spork.Sign(strPrivKey);

    if(spork.CheckSignature()){
        // Test signing successful, proceed
        LogPrintf("CSporkManager::SetPrivKey -- Successfully initialized as spork signer\n");
        strMasterPrivKey = strPrivKey;
        return true;
    } else {
        return false;
    }
}

bool CSporkMessage::Sign(std::string strSignKey)
{
    CKey key;
    CPubKey pubkey;
    std::string strError = "";
    std::string strMessage = boost::lexical_cast<std::string>(nSporkID) + boost::lexical_cast<std::string>(nValue) + boost::lexical_cast<std::string>(nTimeSigned) + sValue;

    if(!CMessageSigner::GetKeysFromSecret(strSignKey, key, pubkey)) {
        LogPrintf("CSporkMessage::Sign -- GetKeysFromSecret() failed, invalid spork key %s\n", strSignKey);
        return false;
    }

    if(!CMessageSigner::SignMessage(strMessage, vchSig, key)) {
        LogPrintf("CSporkMessage::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubkey, vchSig, strMessage, strError)) {
        LogPrintf("CSporkMessage::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSporkMessage::CheckSignature()
{
    std::string strError = "";
    std::string strMessage = boost::lexical_cast<std::string>(nSporkID) + boost::lexical_cast<std::string>(nValue) + boost::lexical_cast<std::string>(nTimeSigned) + sValue;
    CPubKey pubkey(ParseHex(Params().SporkPubKey()));

    if(!CMessageSigner::VerifyMessage(pubkey, vchSig, strMessage, strError)) {
        LogPrintf("CSporkMessage::CheckSignature -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

void CSporkMessage::Relay(CConnman& connman)
{
    CInv inv(MSG_SPORK, GetHash());
    connman.RelayInv(inv);
}
