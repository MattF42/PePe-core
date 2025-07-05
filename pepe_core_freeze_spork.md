# SPORK_21_FREEZE_BLACKLIST Implementation

## Overview

This document describes the implementation of SPORK_21_FREEZE_BLACKLIST, a consensus-level UTXO freeze mechanism that allows the network to temporarily freeze coins associated with blacklisted addresses.

## Features

- **String Payload Support**: Unlike other SPORKs that use integer values, SPORK_21 supports string payloads containing comma-separated address lists.
- **Expiry Mechanism**: Blacklists can include an optional expiry timestamp, after which the freeze is automatically lifted.
- **Consensus Enforcement**: Both block validation (ConnectBlock) and mempool validation (AcceptToMemoryPool) enforce the blacklist.
- **Runtime Updates**: The blacklist can be updated via the SPORK system without requiring hard forks.
- **Backward Compatibility**: Existing SPORKs continue to work unchanged.

## Payload Format

The SPORK_21 payload follows this format:
```
address1,address2,address3,expires=1234567890
```

Where:
- `address1,address2,address3`: Comma-separated list of Bitcoin addresses to blacklist
- `expires=1234567890`: Optional Unix timestamp when the blacklist expires

Examples:
```
# Blacklist two addresses indefinitely
PPeEzZhYgw3R7JG2q4GX8zErhf2mQN5v2H,PQkTiNv7BbRpjTJUt1YRsLrFrhfNT3sxH5

# Blacklist with expiry (expires at timestamp 1734567890)
PPeEzZhYgw3R7JG2q4GX8zErhf2mQN5v2H,PQkTiNv7BbRpjTJUt1YRsLrFrhfNT3sxH5,expires=1734567890
```

## Implementation Details

### New Constants (spork.h)
```cpp
static const int SPORK_21_FREEZE_BLACKLIST = 10017;
static const int64_t SPORK_21_FREEZE_BLACKLIST_DEFAULT = 4070908800ULL; // OFF by default
```

### Extended CSporkMessage Class
- Added `std::string strPayload` member
- Added constructor supporting payload parameter
- Modified serialization to include payload for SPORK_21
- Updated hash calculation to include payload for SPORK_21

### New CSporkManager Methods
- `bool IsBlacklistActive()`: Check if SPORK_21 is active
- `bool IsAddressBlacklisted(const std::string& address)`: Check if specific address is blacklisted
- `std::string GetSporkString(int nSporkID)`: Get string payload for a SPORK
- `bool UpdateSpork(int, int64_t, const std::string&, CConnman&)`: Update SPORK with payload

### Transaction Validation
Blacklist checking is integrated into:

1. **ConnectBlock()** (src/validation.cpp): Blocks containing transactions that spend from blacklisted addresses are rejected
2. **AcceptToMemoryPool()** (src/validation.cpp): Transactions spending from blacklisted addresses are rejected from the mempool

### Error Handling
- Transactions spending from blacklisted addresses return error "bad-txns-blacklisted-address"
- Both block and mempool validation use DoS scores to handle malicious behavior

## Usage Examples

### Activating the Blacklist
```bash
# Enable SPORK_21 with a list of addresses
spork SPORK_21_FREEZE_BLACKLIST "PPeEzZhYgw3R7JG2q4GX8zErhf2mQN5v2H,PQkTiNv7BbRpjTJUt1YRsLrFrhfNT3sxH5"
```

### Adding Expiry
```bash
# Blacklist addresses for 24 hours (expires at timestamp 1734567890)
spork SPORK_21_FREEZE_BLACKLIST "PPeEzZhYgw3R7JG2q4GX8zErhf2mQN5v2H,PQkTiNv7BbRpjTJUt1YRsLrFrhfNT3sxH5,expires=1734567890"
```

### Disabling the Blacklist
```bash
# Set to default off value
spork SPORK_21_FREEZE_BLACKLIST 4070908800
```

## Behavior

### When Active
- **Block Validation**: Blocks containing transactions that spend from blacklisted addresses are rejected
- **Mempool**: New transactions spending from blacklisted addresses cannot enter the mempool
- **Existing UTXOs**: Previously created UTXOs from blacklisted addresses become unspendable

### When Expired or Disabled
- All UTXOs become spendable again (normal behavior resumes)
- No impact on transaction validation

### Consensus Rules
- The blacklist is enforced at the consensus level
- All nodes on the network must agree on the blacklist state
- Signature verification ensures only authorized entities can update the blacklist

## Security Considerations

1. **Authorization**: Only nodes with the proper SPORK signing keys can update the blacklist
2. **Expiry Safety**: Automatic expiry prevents indefinite freezes due to lost keys
3. **Consensus**: All nodes enforce the same blacklist rules
4. **Minimal Impact**: Only affects specified addresses; rest of network operates normally

## Testing

Unit tests are provided in `src/test/spork_freeze_tests.cpp` covering:
- Basic blacklist parsing functionality
- Expiry mechanism
- Serialization with string payloads
- Hash calculation differences
- Manager state checking

## Limitations

- Only supports P2PKH and P2SH address types
- String payload size is limited by network message constraints
- Requires SPORK signing authority to activate/update

## Future Enhancements

Potential future improvements could include:
- Support for address patterns/ranges
- Multi-signature blacklist management
- Gradual unlock mechanisms
- Integration with governance systems