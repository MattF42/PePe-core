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






// Xelis Additions Foztor July 24
//
//
//

#include "blake3.h"
#include "chacha20.h"
#ifdef __linux__
#if defined(__x86_64__)
  #include <emmintrin.h>
  #include <immintrin.h>
  #include <wmmintrin.h>
#elif defined(__aarch64__)
  #include <arm_neon.h>
#endif
#endif


typedef unsigned char byte;
extern double algoHashTotal[20];
extern int algoHashHits[20];

const uint16_t XELIS_MEMORY_SIZE = 32768;
const size_t XELIS_MEMORY_SIZE_V2 = 429*128;

const uint16_t XELIS_SCRATCHPAD_ITERS = 5000;
const uint16_t XELIS_SCRATCHPAD_ITERS_V2 = 3;

const byte XELIS_ITERS = 1;
const uint16_t XELIS_BUFFER_SIZE = 42;
const uint16_t XELIS_BUFFER_SIZE_V2 = XELIS_MEMORY_SIZE_V2 / 2;

const uint16_t XELIS_SLOT_LENGTH = 256;
const int XELIS_TEMPLATE_SIZE = 112;

const byte XELIS_KECCAK_WORDS = 25;
const byte XELIS_BYTES_ARRAY_INPUT = XELIS_KECCAK_WORDS * 8;
const byte XELIS_HASH_SIZE = 32;
const uint16_t XELIS_STAGE_1_MAX = XELIS_MEMORY_SIZE / XELIS_KECCAK_WORDS;


#define XEL_INPUT_LEN (112)
#define XEL_MEMSIZE (429 * 128)
#define XEL_ITERS (3)
#define XEL_HASHSIZE (32)


uint64_t xel_isqrt(uint64_t n) {
	if (n < 2)
		return n;

	uint64_t x = n;
	uint64_t result = 0;
	uint64_t bit = (uint64_t)1 << 62; // The second-to-top bit is set

	// "bit" starts at the highest power of four <= the argument.
	while (bit > x)
		bit >>= 2;

	while (bit != 0)
	{
		if (x >= result + bit)
		{
			x -= result + bit;
			result = (result >> 1) + bit;
		}
		else
		{
			result >>= 1;
		}
		bit >>= 2;
	}

	return result;
}


static inline void blake3(const uint8_t *input, int len, uint8_t *output) {
		blake3_hasher hasher;
			blake3_hasher_init(&hasher);
				blake3_hasher_update(&hasher, input, len);
					blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
}

#define XEL_HASH_SIZE (32)
#define XEL_CHUNK_SIZE (32)
#define XEL_NONCE_SIZE (12)
#define XEL_OUTPUT_SIZE (XEL_MEMSIZE * 8)
#define XEL_CHUNKS (4)
#define XEL_INPUT_LEN (112)


// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xFA, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Helper function to perform GF(2^8) multiplication
static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return result;
}


// AES SubBytes transformation
static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}


// AES ShiftRows transformation
static void shift_rows(uint8_t *state) {
    uint8_t temp[16];
    temp[0]  = state[0];
    temp[1]  = state[5];
    temp[2]  = state[10];
    temp[3]  = state[15];
    temp[4]  = state[4];
    temp[5]  = state[9];
    temp[6]  = state[14];
    temp[7]  = state[3];
    temp[8]  = state[8];
    temp[9]  = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];
    memcpy(state, temp, 16);
}
// AES MixColumns transformation
static void mix_columns(uint8_t *state) {
    uint8_t temp[16];
    for (int i = 0; i < 4; ++i) {
        temp[i * 4 + 0] = gmul(0x02, state[i * 4 + 0]) ^ gmul(0x03, state[i * 4 + 1]) ^ gmul(0x01, state[i * 4 + 2]) ^ gmul(0x01, state[i * 4 + 3]);
        temp[i * 4 + 1] = gmul(0x01, state[i * 4 + 0]) ^ gmul(0x02, state[i * 4 + 1]) ^ gmul(0x03, state[i * 4 + 2]) ^ gmul(0x01, state[i * 4 + 3]);
        temp[i * 4 + 2] = gmul(0x01, state[i * 4 + 0]) ^ gmul(0x01, state[i * 4 + 1]) ^ gmul(0x02, state[i * 4 + 2]) ^ gmul(0x03, state[i * 4 + 3]);
        temp[i * 4 + 3] = gmul(0x03, state[i * 4 + 0]) ^ gmul(0x01, state[i * 4 + 1]) ^ gmul(0x01, state[i * 4 + 2]) ^ gmul(0x02, state[i * 4 + 3]);
    }
    memcpy(state, temp, 16);
}

// AES AddRoundKey transformation
static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}


inline void aes_single_round_no_intrinsics(uint8_t *state, const uint8_t *round_key) {
            sub_bytes(state);
                shift_rows(state);
                    mix_columns(state);
                        add_round_key(state, round_key);
}


void static inline aes_single_round(uint8_t *block, const uint8_t *key)
{
#if defined(__aarch64__)
  aes_single_round_no_intrinsics(block, key);
#endif

#ifdef WIN32
	  aes_single_round_no_intrinsics(block, key);
#endif

#ifdef __linux__
#if defined(__AES__)
#if defined(__x86_64__)
	__m128i block_vec = _mm_loadu_si128((const __m128i *)block);
	__m128i key_vec = _mm_loadu_si128((const __m128i *)key);

	// Perform single AES encryption round
	block_vec = _mm_aesenc_si128(block_vec, key_vec);

	_mm_storeu_si128((__m128i *)block, block_vec);
#endif
#endif
#endif



}
#if defined(__x86_64__)

static inline uint64_t Divide128Div64To64(uint64_t high, uint64_t low, uint64_t divisor, uint64_t *remainder)
{
	uint64_t result;
	__asm__("divq %[v]"
			: "=a"(result), "=d"(*remainder) // Output parametrs, =a for rax, =d for rdx, [v] is an
			// alias for divisor, input paramters "a" and "d" for low and high.
			: [v] "r"(divisor), "a"(low), "d"(high));
	return result;
}

static inline uint64_t XEL_ROTR(uint64_t x, uint32_t r)
{
	asm("rorq %%cl, %0" : "+r"(x) : "c"(r));
	return x;
}

static inline uint64_t XEL_ROTL(uint64_t x, uint32_t r)
{
	asm("rolq %%cl, %0" : "+r"(x) : "c"(r));
	return x;
}
#else

static inline uint64_t Divide128Div64To64(uint64_t high, uint64_t low, uint64_t divisor, uint64_t *remainder)
{
    // Combine high and low into a 128-bit dividend
    __uint128_t dividend = ((__uint128_t)high << 64) | low;

    // Perform division using built-in compiler functions
    *remainder = dividend % divisor;
    return dividend / divisor;
}

static inline uint64_t XEL_ROTR(uint64_t x, uint32_t r)
{
    r %= 64;  // Ensure r is within the range [0, 63] for a 64-bit rotate
    return (x >> r) | (x << (64 - r));
}

static inline uint64_t XEL_ROTL(uint64_t x, uint32_t r)
{
    r %= 64;  // Ensure r is within the range [0, 63] for a 64-bit rotate
    return (x << r) | (x >> (64 - r));
}

#endif

#define COMBINE_UINT64(high, low) (((__uint128_t)(high) << 64) | (low))
static inline __uint128_t combine_uint64(uint64_t high, uint64_t low) {
		return ((__uint128_t)high << 64) | low;
}

void static inline uint64_to_le_bytes(uint64_t value, uint8_t *bytes) {
		for (int i = 0; i < 8; i++)
				{
							bytes[i] = value & 0xFF;
									value >>= 8;
										}
}

uint64_t static inline le_bytes_to_uint64(const uint8_t *bytes) {
		uint64_t value = 0;
			for (int i = 7; i >= 0; i--)
						value = (value << 8) | bytes[i];
				return value;
}




static inline uint64_t udiv(uint64_t high, uint64_t low, uint64_t divisor)
{
		uint64_t remainder;

			if (high < divisor)
					{
								return Divide128Div64To64(high, low, divisor, &remainder);
									}
				else
						{
									uint64_t qhi = Divide128Div64To64(0, high, divisor, &high);
											return Divide128Div64To64(high, low, divisor, &remainder);
												}
}



static inline uint64_t isqrt(uint64_t n)
{
	  if (n < 2)
		    {
			        return n;
				  }

	    uint64_t x = n;
	      uint64_t y = (x + 1) >> 1;

	        while (y < x)
			  {
				      x = y;
				          y = (x + n / x) >> 1;
					    }

		  return x;
}



// __attribute__((noinline))
static inline uint64_t case_0(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return XEL_ROTL(c, i * j) ^ b; 
}
// __attribute__((noinline))
static inline uint64_t case_1(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return XEL_ROTR(c, i * j) ^ a; 
}
// __attribute__((noinline))
static inline uint64_t case_2(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return a ^ b ^ c; 
}
// __attribute__((noinline))
static inline uint64_t case_3(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return (a + b) * c; 
}
// __attribute__((noinline))
static inline uint64_t case_4(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return (b - c) * a; 
}
// __attribute__((noinline))
static inline uint64_t case_5(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return c - a + b; 
}
// __attribute__((noinline))
static inline uint64_t case_6(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return a - b + c; 
}
// __attribute__((noinline))
static inline uint64_t case_7(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return b * c + a; 
}
// __attribute__((noinline))
static inline uint64_t case_8(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return c * a + b; 
}
// __attribute__((noinline))
static inline uint64_t case_9(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return a * b * c; 
}
// __attribute__((noinline))
static inline uint64_t case_10(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return COMBINE_UINT64(a,b) % (c | 1); 
}
// __attribute__((noinline))
static inline uint64_t case_11(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  __uint128_t t2 = COMBINE_UINT64(XEL_ROTL(result, r), a | 2);
  return (t2 > COMBINE_UINT64(b,c)) ? c : COMBINE_UINT64(b,c) % t2;
}
// __attribute__((noinline))
static inline uint64_t case_12(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return udiv(c, a, b | 4); 
}
// __attribute__((noinline))
static inline uint64_t case_13(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  __uint128_t t1 = COMBINE_UINT64(XEL_ROTL(result, r), b);
  __uint128_t t2 = COMBINE_UINT64(a, c | 8);
  return (t1 > t2) ? t1 / t2 : a ^ b;
}
// __attribute__((noinline))
static inline uint64_t case_14(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return (COMBINE_UINT64(b,a) * c) >> 64; 
}
// __attribute__((noinline))
static inline uint64_t case_15(uint64_t a, uint64_t b, uint64_t c, int r, uint64_t result, int i, int j) { 
  return (COMBINE_UINT64(a,c) * COMBINE_UINT64(XEL_ROTR(result, r), b)) >> 64; 
}



typedef uint64_t (*operation_func)(uint64_t, uint64_t, uint64_t, int, uint64_t, int, int);
operation_func operations[] = {
	    case_0, case_1, case_2, case_3, case_4, case_5, case_6, case_7,
	        case_8, case_9, case_10, case_11, case_12, case_13, case_14, case_15,
		    // Add other functions for cases 10-15
		    };
		    //

//
// void xel_stage_3(uint64_t *scratch_pad, workerData_xelis_v2 &worker)
void xel_stage_3(uint64_t *scratch_pad)
{
    const uint8_t key[17] = "xelishash-pow-v2";
    uint8_t block[16] = {0};

    uint64_t *mem_buffer_a = scratch_pad;
    uint64_t *mem_buffer_b = scratch_pad + XELIS_BUFFER_SIZE_V2;

    uint64_t addr_a = mem_buffer_b[XELIS_BUFFER_SIZE_V2 - 1];
    uint64_t addr_b = mem_buffer_a[XELIS_BUFFER_SIZE_V2 - 1] >> 32;
    size_t r = 0;


    #pragma unroll 3
    for (size_t i = 0; i < XELIS_SCRATCHPAD_ITERS_V2; ++i) {
        uint64_t mem_a = mem_buffer_a[addr_a % XELIS_BUFFER_SIZE_V2];
        uint64_t mem_b = mem_buffer_b[addr_b % XELIS_BUFFER_SIZE_V2];

        // std::copy(&mem_b, &mem_b + 8, block);
        // std::copy(&mem_a, &mem_a + 8, block + 8);

        uint64_to_le_bytes(mem_b, block);
		    uint64_to_le_bytes(mem_a, block + 8);

        aes_single_round(block, key);

        uint64_t hash1 = 0, hash2 = 0;
        // hash1 = ((uint64_t*)block)[0]; // simple assignment, slower than SIMD on my CPU
        hash1 = le_bytes_to_uint64(block);
        // std::copy(block, block + 8, &hash1);
        // hash1 = _byteswap_uint64(hash1);
        hash2 = mem_a ^ mem_b;

        addr_a = ~(hash1 ^ hash2);

        // printf("pre result: %llu\n", result);

        for (size_t j = 0; j < XELIS_BUFFER_SIZE_V2; ++j) {
            uint64_t a = mem_buffer_a[(addr_a % XELIS_BUFFER_SIZE_V2)];
            uint64_t b = mem_buffer_b[~XEL_ROTR(addr_a, r) % XELIS_BUFFER_SIZE_V2];
            uint64_t c = (r < XELIS_BUFFER_SIZE_V2) ? mem_buffer_a[r] : mem_buffer_b[r - XELIS_BUFFER_SIZE_V2];
            r = (r+1) % XELIS_MEMORY_SIZE_V2;

            // printf("a %llu, b %llu, c %llu, ", a, b, c);
            uint64_t v;
            uint32_t idx = XEL_ROTL(addr_a, (uint32_t)c) & 0xF;
            v = operations[idx](a,b,c,r,addr_a,i,j);

            addr_a = XEL_ROTL(addr_a ^ v, 1);

            uint64_t t = mem_buffer_a[XELIS_BUFFER_SIZE_V2 - j - 1] ^ addr_a;
            mem_buffer_a[XELIS_BUFFER_SIZE_V2 - j - 1] = t;
            mem_buffer_b[j] ^= XEL_ROTR(t, (uint32_t)addr_a);
        }
        // printf("post result: %llu\n", result);
        addr_b = isqrt(addr_a);
    }

  // Crc32 crc32;
  // crc32.input((uint8_t *)scratch_pad, XELIS_MEMORY_SIZE_V2 * 8);
  // printf("%llu\n", crc32.result());
}

void xel_stage_1(const uint8_t *input, size_t input_len, uint8_t scratch_pad[XEL_OUTPUT_SIZE])
{
        uint8_t key[XEL_CHUNK_SIZE * XEL_CHUNKS] = {0};
        uint8_t input_hash[XEL_HASH_SIZE];
        uint8_t buffer[XEL_CHUNK_SIZE * 2];
        memcpy(key, input, XEL_INPUT_LEN);
        // memcpy(key, input, sizeof(input));
        blake3(input, input_len, buffer);

        uint8_t *t = scratch_pad;
                                
        memcpy(buffer + XEL_CHUNK_SIZE, key + 0 * XEL_CHUNK_SIZE, XEL_CHUNK_SIZE);
        blake3(buffer, XEL_CHUNK_SIZE * 2, input_hash);
        chacha_encrypt(input_hash, buffer, NULL, t, XEL_OUTPUT_SIZE / XEL_CHUNKS, 8);

        t += XEL_OUTPUT_SIZE / XEL_CHUNKS;
        memcpy(buffer, input_hash, XEL_CHUNK_SIZE);
        memcpy(buffer + XEL_CHUNK_SIZE, key + 1 * XEL_CHUNK_SIZE, XEL_CHUNK_SIZE);
        blake3(buffer, XEL_CHUNK_SIZE * 2, input_hash);
        chacha_encrypt(input_hash, t - XEL_NONCE_SIZE, NULL, t, XEL_OUTPUT_SIZE / XEL_CHUNKS, 8);
                        
        t += XEL_OUTPUT_SIZE / XEL_CHUNKS;
        memcpy(buffer, input_hash, XEL_CHUNK_SIZE);
        memcpy(buffer + XEL_CHUNK_SIZE, key + 2 * XEL_CHUNK_SIZE, XEL_CHUNK_SIZE);
        blake3(buffer, XEL_CHUNK_SIZE * 2, input_hash);
        chacha_encrypt(input_hash, t - XEL_NONCE_SIZE, NULL, t, XEL_OUTPUT_SIZE / XEL_CHUNKS, 8);

        t += XEL_OUTPUT_SIZE / XEL_CHUNKS;
        memcpy(buffer, input_hash, XEL_CHUNK_SIZE);
        memcpy(buffer + XEL_CHUNK_SIZE, key + 3 * XEL_CHUNK_SIZE, XEL_CHUNK_SIZE);
        blake3(buffer, XEL_CHUNK_SIZE * 2, input_hash);
        chacha_encrypt(input_hash, t - XEL_NONCE_SIZE, NULL, t, XEL_OUTPUT_SIZE / XEL_CHUNKS, 8);
}       


#define XEL_KEY "xelishash-pow-v2"
#define XEL_BUFSIZE (XEL_MEMSIZE / 2)



static const int32_t KeyDataSize = 48;
static const int32_t rounds = 20;

static const uint32_t ConstState[4] = {1634760805, 857760878, 2036477234, 1797285236}; //"expand 32-byte k";;

void ChaCha20SetNonce(uint8_t *state, const uint8_t *Nonce)
{
		memcpy(state + 36, Nonce, 12);
}


void ChaCha20EncryptBytes(uint8_t *state, uint8_t *In, uint8_t *Out, size_t Size, uint32_t rounds)
{

	// portable chacha, no simd
	uint8_t *CurrentIn = In;
	uint8_t *CurrentOut = Out;
	uint64_t RemainingBytes = Size;
	uint32_t *state_dwords = (uint32_t *)state;
	uint32_t b[16];
	while (1)
	{
		b[0] = ConstState[0];
		b[1] = ConstState[1];
		b[2] = ConstState[2];
		b[3] = ConstState[3];
		memcpy(((uint8_t *)b) + 16, state, 48);

		for (int i = rounds; i > 0; i -= 2)
		{
			b[0] = b[0] + b[4];
			b[12] = (b[12] ^ b[0]) << 16 | (b[12] ^ b[0]) >> 16;
			b[8] = b[8] + b[12];
			b[4] = (b[4] ^ b[8]) << 12 | (b[4] ^ b[8]) >> 20;
			b[0] = b[0] + b[4];
			b[12] = (b[12] ^ b[0]) << 8 | (b[12] ^ b[0]) >> 24;
			b[8] = b[8] + b[12];
			b[4] = (b[4] ^ b[8]) << 7 | (b[4] ^ b[8]) >> 25;
			b[1] = b[1] + b[5];
			b[13] = (b[13] ^ b[1]) << 16 | (b[13] ^ b[1]) >> 16;
			b[9] = b[9] + b[13];
			b[5] = (b[5] ^ b[9]) << 12 | (b[5] ^ b[9]) >> 20;
			b[1] = b[1] + b[5];
			b[13] = (b[13] ^ b[1]) << 8 | (b[13] ^ b[1]) >> 24;
			b[9] = b[9] + b[13];
			b[5] = (b[5] ^ b[9]) << 7 | (b[5] ^ b[9]) >> 25;
			b[2] = b[2] + b[6];
			b[14] = (b[14] ^ b[2]) << 16 | (b[14] ^ b[2]) >> 16;
			b[10] = b[10] + b[14];
			b[6] = (b[6] ^ b[10]) << 12 | (b[6] ^ b[10]) >> 20;
			b[2] = b[2] + b[6];
			b[14] = (b[14] ^ b[2]) << 8 | (b[14] ^ b[2]) >> 24;
			b[10] = b[10] + b[14];
			b[6] = (b[6] ^ b[10]) << 7 | (b[6] ^ b[10]) >> 25;
			b[3] = b[3] + b[7];
			b[15] = (b[15] ^ b[3]) << 16 | (b[15] ^ b[3]) >> 16;
			b[11] = b[11] + b[15];
			b[7] = (b[7] ^ b[11]) << 12 | (b[7] ^ b[11]) >> 20;
			b[3] = b[3] + b[7];
			b[15] = (b[15] ^ b[3]) << 8 | (b[15] ^ b[3]) >> 24;
			b[11] = b[11] + b[15];
			b[7] = (b[7] ^ b[11]) << 7 | (b[7] ^ b[11]) >> 25;
			b[0] = b[0] + b[5];
			b[15] = (b[15] ^ b[0]) << 16 | (b[15] ^ b[0]) >> 16;
			b[10] = b[10] + b[15];
			b[5] = (b[5] ^ b[10]) << 12 | (b[5] ^ b[10]) >> 20;
			b[0] = b[0] + b[5];
			b[15] = (b[15] ^ b[0]) << 8 | (b[15] ^ b[0]) >> 24;
			b[10] = b[10] + b[15];
			b[5] = (b[5] ^ b[10]) << 7 | (b[5] ^ b[10]) >> 25;
			b[1] = b[1] + b[6];
			b[12] = (b[12] ^ b[1]) << 16 | (b[12] ^ b[1]) >> 16;
			b[11] = b[11] + b[12];
			b[6] = (b[6] ^ b[11]) << 12 | (b[6] ^ b[11]) >> 20;
			b[1] = b[1] + b[6];
			b[12] = (b[12] ^ b[1]) << 8 | (b[12] ^ b[1]) >> 24;
			b[11] = b[11] + b[12];
			b[6] = (b[6] ^ b[11]) << 7 | (b[6] ^ b[11]) >> 25;
			b[2] = b[2] + b[7];
			b[13] = (b[13] ^ b[2]) << 16 | (b[13] ^ b[2]) >> 16;
			b[8] = b[8] + b[13];
			b[7] = (b[7] ^ b[8]) << 12 | (b[7] ^ b[8]) >> 20;
			b[2] = b[2] + b[7];
			b[13] = (b[13] ^ b[2]) << 8 | (b[13] ^ b[2]) >> 24;
			b[8] = b[8] + b[13];
			b[7] = (b[7] ^ b[8]) << 7 | (b[7] ^ b[8]) >> 25;
			b[3] = b[3] + b[4];
			b[14] = (b[14] ^ b[3]) << 16 | (b[14] ^ b[3]) >> 16;
			b[9] = b[9] + b[14];
			b[4] = (b[4] ^ b[9]) << 12 | (b[4] ^ b[9]) >> 20;
			b[3] = b[3] + b[4];
			b[14] = (b[14] ^ b[3]) << 8 | (b[14] ^ b[3]) >> 24;
			b[9] = b[9] + b[14];
			b[4] = (b[4] ^ b[9]) << 7 | (b[4] ^ b[9]) >> 25;
		}

		for (uint32_t i = 0; i < 4; ++i)
		{
			b[i] += ConstState[i];
		}
		for (uint32_t i = 0; i < 12; ++i)
		{
			b[i + 4] += state_dwords[i];
		}

		++state_dwords[8]; // counter

		if (RemainingBytes >= 64)
		{
			if (In)
			{
				uint32_t *In32bits = (uint32_t *)CurrentIn;
				uint32_t *Out32bits = (uint32_t *)CurrentOut;
				for (uint32_t i = 0; i < 16; i++)
				{
					Out32bits[i] = In32bits[i] ^ b[i];
				}
			}
			else
				memcpy(CurrentOut, b, 64);

			if (In)
				CurrentIn += 64;
			CurrentOut += 64;
			RemainingBytes -= 64;
			if (RemainingBytes == 0)
				return;
			continue;
		}
		else
		{
			if (In)
			{
				for (int32_t i = 0; i < RemainingBytes; i++)
					CurrentOut[i] = CurrentIn[i] ^ ((uint8_t *)b)[i];
			}
			else
				memcpy(CurrentOut, b, RemainingBytes);
			return;
		}
	}
}



void ChaCha20SetKey(uint8_t *state, const uint8_t *Key)
{
		memcpy(state, Key, 32);
}

void chacha_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds)
{
		uint8_t state[48] = {0};
			ChaCha20SetKey(state, key);
				ChaCha20SetNonce(state, nonce);
					ChaCha20EncryptBytes(state, in, out, bytes, rounds);
}


// Blake3
//
//
//
   


#include "blake3.c"
#include "blake3_dispatch.c"
#include "blake3_portable.c"

// template<typename T1>
void xelis_goldenhash()
{


			uint64_t *scratch = (uint64_t *)calloc(XEL_MEMSIZE, sizeof(uint64_t));
			uint8_t *scratch_uint8 = (uint8_t *)scratch;
			uint8_t *blankinput = (uint8_t *)calloc(XEL_INPUT_LEN, sizeof(uint8_t));


			xel_stage_1(blankinput, XEL_INPUT_LEN, scratch_uint8);
			xel_stage_3(scratch);
			uint8_t hashResult[XEL_HASHSIZE];
			blake3((uint8_t*)scratch, XEL_OUTPUT_SIZE, hashResult);

			uint8_t gold[XEL_HASHSIZE] = {
                                126, 219, 112, 240, 116, 133, 115,
                                144, 39, 40, 164, 105, 30, 158, 45,
                                126, 64, 67, 238, 52, 200, 35, 161, 19,
                                144, 211, 214, 225, 95, 190, 146, 27};

                        if (memcmp(gold, hashResult, XEL_HASHSIZE))
                                        LogPrintf("XELV2: GOLD Failed\n");
                        else
                                        LogPrintf("XELV2: GOLD Passed\n");
			free(scratch);
			free(blankinput);
			return;
}

void xelis_hash_v2(const void* data, size_t len, uint8_t hashResult[XEL_HASHSIZE])
{
	                // xelis_goldenhash();
			static uint8_t pblank[1];

			// LogPrintf("XEL2: Len is %d\n", len);

			uint64_t *scratch = (uint64_t *)calloc(XEL_MEMSIZE, sizeof(uint64_t));
			uint8_t *scratch_uint8 = (uint8_t *)scratch;
			uint8_t *blankinput = (uint8_t *)calloc(XEL_INPUT_LEN, sizeof(uint8_t));
			std::memcpy(blankinput, data, len);
			blankinput[len] = '\0';


			int j;

			/*
			LogPrintf("Stage1 Input as hex: ");
			for(j = 0; j < len; ++j)
				  LogPrintf("%02x", blankinput[j]);
				  LogPrintf(": \n ");
				  */


			xel_stage_1(blankinput, XEL_INPUT_LEN, scratch_uint8);
			xel_stage_3(scratch);
			blake3((uint8_t*)scratch, XEL_OUTPUT_SIZE, hashResult);
			free(scratch);
			free(blankinput);
			return;

}
template<typename T1>
void pre_xelis_hash_v2(const T1 pbegin, const T1 pend, uint256 hashPrevBlock, uint8_t hash_result[XEL_HASHSIZE]) {
	static unsigned char pblank[1];
	/*
	if(pbegin == pend) {
			LogPrintf("pre_xelis_hash_v2: pbegin == pend\n");
	}
	*/
	// xelis_hash_v2((pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]), PrevBlockHash, hash_result);
	xelis_hash_v2((static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]),  hash_result);
	return;
}



uint256 CBlockHeader::GetPOWHash() const
{
uint256 PePeHash;

        // LogPrintf("CBlockHeader::GetHash %s\n",BEGIN(nVersion));
         if(nVersion & 0x8000) {
           uint8_t hash_result[XELIS_HASH_SIZE] = {0};
           uint256 res;
           int i,j,temp;
           pre_xelis_hash_v2(BEGIN(nVersion), END(nNonce), hashPrevBlock, hash_result);
           /*
           LogPrintf("CBlockHeader:: SWAP: ");
           for (i = 0, j = XELIS_HASH_SIZE - 1; i < j; i++, j--) { // loop to swap element
                   temp = hash_result[i];
                   LogPrintf("%02x", hash_result[i]);
                   hash_result[i] = hash_result[j];
                   hash_result[j] = temp;
           }
           LogPrintf("\n");
           */
           std::memcpy(&res, hash_result, sizeof(hash_result));
            // LogPrintf("CBlockHeader::xelis_hash %s\n",res.ToString());
           return res;
    }
    PePeHash = pepe_hash(BEGIN(nVersion), END(nNonce), hashPrevBlock);
       // LogPrintf("CBlockHeader::pepe_hash - %s \n",PePeHash.ToString());
    return PePeHash;

}



uint256 CBlockHeader::GetHash() const
{
uint256 PePeHash;

        // LogPrintf("CBlockHeader::GetHash %s\n",BEGIN(nVersion));
         if(nVersion & 0x8000) {
           uint8_t hash_result[XELIS_HASH_SIZE] = {0};
           uint256 res;
           int i,j,temp;
            // LogPrintf("CBlockHeader::GetHash Xel Starts\n");
           pre_xelis_hash_v2(BEGIN(nVersion), END(nNonce), hashPrevBlock, hash_result);
           /*
           LogPrintf("CBlockHeader:: SWAP: ");
           for (i = 0, j = XELIS_HASH_SIZE - 1; i < j; i++, j--) { // loop to swap element
                   temp = hash_result[i];
                   LogPrintf("%02x", hash_result[i]);
                   hash_result[i] = hash_result[j];
                   hash_result[j] = temp;
           }
           LogPrintf("\n");
           */
           std::memcpy(&res, hash_result, sizeof(hash_result));
            // LogPrintf("CBlockHeader::xelis_hash %s\n",res.ToString());
           return res;
    }
    PePeHash = pepe_hash(BEGIN(nVersion), END(nNonce), hashPrevBlock);
       // LogPrintf("CBlockHeader::pepe_hash - %s \n",PePeHash.ToString());
    return PePeHash;
}



std::string CBlock::ToString() const
{
    // LogPrintf("CBlockHeader::ToString\n");
    // LogPrintf("CBlockHeader::nVersion %s\n",nVersion);
    // LogPrintf("CBlockHeader::hashPrevBlock.ToString %s\n",hashPrevBlock.ToString());
    // LogPrintf("CBlockHeader::GetHash.ToString %s\n",GetHash().ToString());
    // LogPrintf("CBlockHeader::nVersion again %s\n",nVersion);
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
