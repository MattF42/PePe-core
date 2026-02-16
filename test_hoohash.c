// Simple test for HoohashV110 algorithm
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypto/hoohash/hoohash.h"

void print_hash(const char* label, const uint8_t* hash, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    printf("Testing HoohashV110 implementation\n");
    printf("===================================\n\n");
    
    // Test 1: Empty input
    {
        uint8_t input[] = "";
        uint8_t output[32] = {0};
        hoohashv110(input, 0, output);
        print_hash("Empty input", output, 32);
    }
    
    // Test 2: Simple string
    {
        uint8_t input[] = "Hello, Hoohash!";
        uint8_t output[32] = {0};
        hoohashv110(input, strlen((char*)input), output);
        print_hash("'Hello, Hoohash!'", output, 32);
    }
    
    // Test 3: Block header-like data (80 bytes)
    {
        uint8_t header[80];
        memset(header, 0, sizeof(header));
        // Simulate a block header structure:
        // version (4), prevhash (32), merkleroot (32), time (4), bits (4), nonce (4)
        *(uint32_t*)&header[0] = 0x20000000;  // version
        *(uint32_t*)&header[68] = 0x12345678; // time
        *(uint32_t*)&header[72] = 0x1e0fffff; // bits
        *(uint32_t*)&header[76] = 0x00000001; // nonce
        
        uint8_t output[32] = {0};
        hoohashv110(header, sizeof(header), output);
        print_hash("Block header (nonce=1)", output, 32);
        
        // Test with different nonce
        *(uint32_t*)&header[76] = 0x00000100; // nonce = 256
        hoohashv110(header, sizeof(header), output);
        print_hash("Block header (nonce=256)", output, 32);
    }
    
    // Test 4: Verify determinism
    {
        uint8_t input[] = "Determinism test";
        uint8_t output1[32] = {0};
        uint8_t output2[32] = {0};
        
        hoohashv110(input, strlen((char*)input), output1);
        hoohashv110(input, strlen((char*)input), output2);
        
        if (memcmp(output1, output2, 32) == 0) {
            printf("\nDeterminism test: PASSED (identical hashes)\n");
        } else {
            printf("\nDeterminism test: FAILED (different hashes!)\n");
            return 1;
        }
    }
    
    printf("\nAll tests completed successfully!\n");
    return 0;
}
