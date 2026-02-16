# HoohashV110 PoW Implementation

## Overview

HoohashV110 is a proof-of-work algorithm integrated into PePe-core for use on regtest and devnet networks. On mainnet and testnet, the existing PoW algorithms (pepe_hash and XelisV2) remain unchanged.

## Network-Specific Behavior

- **Mainnet**: Uses existing PoW selection (pepe_hash or XelisV2 based on nVersion & 0x8000)
- **Testnet**: Uses existing PoW selection (pepe_hash or XelisV2 based on nVersion & 0x8000)
- **Regtest**: Uses HoohashV110 from genesis (height 0)
- **Devnet**: Uses HoohashV110 from genesis (height 0)

## Implementation Details

### Files Added/Modified

#### New Files
- `src/crypto/hoohash/hoohash.h` - HoohashV110 interface
- `src/crypto/hoohash/hoohash.c` - HoohashV110 implementation

#### Modified Files
- `src/primitives/block.cpp` - Integrated hoohash into GetPOWHash() and GetHash()
- `src/Makefile.am` - Added hoohash sources to build
- `src/httpserver.cpp` - Fixed missing #include <deque> (pre-existing issue)

### Algorithm Description

HoohashV110 is a memory-hard, compute-intensive PoW algorithm that:

1. Takes the full block header (80 bytes) as input
2. Performs a BLAKE3 hash on the input
3. Generates a 64x64 matrix using xoshiro256** PRNG seeded with the hash
4. Performs complex matrix multiplication with non-linear transformations
5. Applies a final BLAKE3 hash to produce the 32-byte output

### Extranonce Handling

The algorithm correctly handles extranonce changes:
- The entire block header (including merkle root) is hashed
- Changes to the merkle root (via extranonce) propagate to the PoW hash
- This is identical to the existing PoW algorithms
- Mining pools can use extranonce as usual

### Security Considerations

1. **Fixed UB Issues**: The reference implementation had unaligned memory reads that could cause undefined behavior. These have been fixed using safe byte-wise reads.

2. **Debug Prints Removed**: All printf/debug statements from the reference code have been removed for production use.

3. **Deterministic Behavior**: The algorithm produces consistent results across platforms and compiler settings.

4. **Math Operations**: Uses standard C math library functions (sin, cos, exp, sqrt) which may have slight variations across platforms, but this is acceptable for PoW algorithms.

## Building

The hoohash implementation is automatically built as part of the crypto library:

```bash
./autogen.sh
./configure --disable-wallet --disable-tests --disable-bench
make
```

### Dependencies

- BLAKE3 (already included in PePe-core)
- C math library (-lm)
- C++11 compiler

## Testing

### Unit Tests

Standalone tests verified:
- Deterministic output for same input
- Different outputs for different inputs
- Extranonce propagation via merkle root
- Nonce field changes affect output

### Regtest Testing

To test HoohashV110 on regtest:

```bash
./PEPEPOWd -regtest -daemon
./PEPEPOW-cli -regtest generate 1
```

The generated block will use HoohashV110 for its proof-of-work.

## Performance

HoohashV110 is computationally intensive due to:
- 64x64 matrix operations
- Complex non-linear mathematical transformations
- Multiple BLAKE3 hash operations

This makes it suitable for fair CPU mining on regtest/devnet while being too slow for mainnet production use.

## Mainnet Safety

**Important**: HoohashV110 is NOT active on mainnet or testnet. The network detection logic in `block.cpp` ensures that existing PoW algorithms continue to be used on production networks.

## References

- Original HoohashV110: https://github.com/HoosatNetwork/hoohash/
- Reference commit: 9634f11410a2d71be21086e813263fa007fb6810
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3
