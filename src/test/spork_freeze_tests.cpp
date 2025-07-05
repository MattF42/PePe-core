// Copyright (c) 2024 The PePe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spork.h"
#include "test_PEPEPOW.h"
#include "chainparams.h"
#include "base58.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(spork_freeze_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(spork_blacklist_parsing)
{
    // Test basic blacklist parsing functionality
    CSporkMessage spork(SPORK_21_FREEZE_BLACKLIST, 1, GetAdjustedTime(), "address1,address2,address3");
    
    // Test that the spork has the correct payload
    BOOST_CHECK_EQUAL(spork.strPayload, "address1,address2,address3");
    BOOST_CHECK_EQUAL(spork.nSporkID, SPORK_21_FREEZE_BLACKLIST);
}

BOOST_AUTO_TEST_CASE(spork_blacklist_expiry)
{
    // Test blacklist with expiry
    int64_t futureTime = GetAdjustedTime() + 3600; // 1 hour from now
    std::string payload = "address1,address2,expires=" + std::to_string(futureTime);
    
    CSporkMessage spork(SPORK_21_FREEZE_BLACKLIST, 1, GetAdjustedTime(), payload);
    BOOST_CHECK_EQUAL(spork.strPayload, payload);
}

BOOST_AUTO_TEST_CASE(spork_manager_blacklist_inactive_by_default)
{
    // Test that blacklist is inactive by default
    BOOST_CHECK(!sporkManager.IsBlacklistActive());
    BOOST_CHECK(!sporkManager.IsAddressBlacklisted("any_address"));
}

BOOST_AUTO_TEST_CASE(spork_manager_address_checking)
{
    // This test requires that we can activate the spork, but without 
    // private keys we can't sign it. We'll test the parsing logic directly.
    
    // Test parsing of comma-separated addresses
    std::string testAddress1 = "address1";
    std::string testAddress2 = "address2";
    std::string testAddress3 = "address3";
    
    // Create a fake active spork entry for testing
    CSporkMessage testSpork(SPORK_21_FREEZE_BLACKLIST, 1, GetAdjustedTime(), 
                           testAddress1 + "," + testAddress2 + "," + testAddress3);
    
    // Note: In a real test environment, we would need to set up the spork manager
    // with proper signing keys to test the full functionality.
    
    BOOST_CHECK_EQUAL(testSpork.nSporkID, SPORK_21_FREEZE_BLACKLIST);
    BOOST_CHECK_EQUAL(testSpork.strPayload, "address1,address2,address3");
}

BOOST_AUTO_TEST_CASE(spork_serialization_with_payload)
{
    // Test that serialization works correctly with string payload
    CSporkMessage original(SPORK_21_FREEZE_BLACKLIST, 1, GetAdjustedTime(), "test_payload");
    
    // Test hash calculation includes payload
    uint256 hash1 = original.GetHash();
    
    CSporkMessage modified(SPORK_21_FREEZE_BLACKLIST, 1, original.nTimeSigned, "different_payload");
    uint256 hash2 = modified.GetHash();
    
    // Hashes should be different when payloads are different
    BOOST_CHECK(hash1 != hash2);
    
    // Test that regular SPORKs don't include payload in hash
    CSporkMessage regularSpork(SPORK_2_INSTANTSEND_ENABLED, 1, GetAdjustedTime(), "ignored_payload");
    CSporkMessage regularSpork2(SPORK_2_INSTANTSEND_ENABLED, 1, regularSpork.nTimeSigned, "different_ignored");
    
    // These should have the same hash since payload is ignored for non-blacklist SPORKs
    BOOST_CHECK(regularSpork.GetHash() == regularSpork2.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()