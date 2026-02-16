// Test to verify extranonce changes propagate via merkle root
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypto/hoohash/hoohash.h"

void print_hash(const uint8_t* hash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
}

int main() {
    printf("Testing extranonce propagation via merkle root\n");
    printf("===============================================\n\n");
    
    // Simulate a block header: version (4), prevhash (32), merkleroot (32), time (4), bits (4), nonce (4)
    uint8_t header[80];
    memset(header, 0, sizeof(header));
    
    *(uint32_t*)&header[0] = 0x20000000;  // version
    *(uint32_t*)&header[68] = 0x12345678; // time
    *(uint32_t*)&header[72] = 0x1e0fffff; // bits
    *(uint32_t*)&header[76] = 0x00000001; // nonce
    
    // Test 1: Change merkle root (simulating extranonce change)
    printf("Test 1: Merkle root changes (extranonce)\n");
    printf("-----------------------------------------\n");
    
    uint8_t output1[32] = {0};
    uint8_t output2[32] = {0};
    
    // First merkle root
    memset(&header[4], 0xAA, 32);
    hoohashv110(header, sizeof(header), output1);
    printf("Merkle root 1: ");
    print_hash(&header[4], 32);
    printf("\nPoW hash 1:    ");
    print_hash(output1, 32);
    printf("\n\n");
    
    // Second merkle root (changed by 1 byte)
    header[4] = 0xAB;  // Change first byte of merkle root
    hoohashv110(header, sizeof(header), output2);
    printf("Merkle root 2: ");
    print_hash(&header[4], 32);
    printf("\nPoW hash 2:    ");
    print_hash(output2, 32);
    printf("\n\n");
    
    // Verify hashes are different
    if (memcmp(output1, output2, 32) != 0) {
        printf("✓ PoW hashes are different when merkle root changes\n");
        printf("  This confirms extranonce changes will affect the PoW hash.\n\n");
    } else {
        printf("✗ FAILED: PoW hashes are identical!\n\n");
        return 1;
    }
    
    // Test 2: Change nonce (direct nonce field)
    printf("Test 2: Nonce field changes\n");
    printf("---------------------------\n");
    
    // Reset merkle root
    memset(&header[4], 0xAA, 32);
    
    *(uint32_t*)&header[76] = 0x00000001; // nonce = 1
    hoohashv110(header, sizeof(header), output1);
    printf("Nonce = 1:   ");
    print_hash(output1, 32);
    printf("\n");
    
    *(uint32_t*)&header[76] = 0x00000002; // nonce = 2
    hoohashv110(header, sizeof(header), output2);
    printf("Nonce = 2:   ");
    print_hash(output2, 32);
    printf("\n\n");
    
    if (memcmp(output1, output2, 32) != 0) {
        printf("✓ PoW hashes are different when nonce changes\n\n");
    } else {
        printf("✗ FAILED: PoW hashes are identical!\n\n");
        return 1;
    }
    
    printf("All extranonce tests passed!\n");
    return 0;
}
