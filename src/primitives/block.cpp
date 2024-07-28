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
#if defined(__x86_64__)
  #include <emmintrin.h>
  #include <immintrin.h>
  #include <wmmintrin.h>
#elif defined(__aarch64__)
  #include <arm_neon.h>
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

#if defined(__x86_64__)

void static inline aes_single_round(uint8_t *block, const uint8_t *key)
{
	__m128i block_vec = _mm_loadu_si128((const __m128i *)block);
	__m128i key_vec = _mm_loadu_si128((const __m128i *)key);

	// Perform single AES encryption round
	block_vec = _mm_aesenc_si128(block_vec, key_vec);

	_mm_storeu_si128((__m128i *)block, block_vec);
}

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

#else // aarch64

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



void xel_stage_1(const uint8_t *input, uint64_t *sp, size_t input_len)
{
	  const size_t chunk_size = 32;
	    const size_t nonce_size = 12;
	      const size_t output_size = XELIS_MEMORY_SIZE_V2 * 8;
	        const size_t chunks = 4;

		  uint8_t *t = reinterpret_cast<uint8_t *>(sp);
		    uint8_t key[chunk_size * chunks] = {0};
		      uint8_t K2[32] = {0};
		        uint8_t buffer[chunk_size*2] = {0};

			  memcpy(key, input, input_len);
			    blake3(input, input_len, buffer);

			      memcpy(buffer + chunk_size, key, chunk_size);
			        blake3(buffer, chunk_size*2, K2);
				  chacha_encrypt(K2, buffer, NULL, t, output_size / chunks, 8);

				    t += output_size / chunks;

				      memcpy(buffer, K2, chunk_size);
				        memcpy(buffer + chunk_size, key + chunk_size, chunk_size);
					  blake3(buffer, chunk_size*2, K2);
					    chacha_encrypt(K2, t - nonce_size, NULL, t, output_size / chunks, 8);

					      t += output_size / chunks;

					        memcpy(buffer, K2, chunk_size);
						  memcpy(buffer + chunk_size, key + 2*chunk_size, chunk_size);
						    blake3(buffer, chunk_size*2, K2);
						      chacha_encrypt(K2, t - nonce_size, NULL, t, output_size / chunks, 8);

						        t += output_size / chunks;

							  memcpy(buffer, K2, chunk_size);
							    memcpy(buffer + chunk_size, key + 3*chunk_size, chunk_size);
							      blake3(buffer, chunk_size*2, K2);
							        chacha_encrypt(K2, t - nonce_size, NULL, t, output_size / chunks, 8);

								  // Crc32 crc32;
								  //   // crc32.input((uint8_t *)sp, XELIS_MEMORY_SIZE_V2 * 8);
								  //     // printf("%lu\n", crc32.result());
								  //       // Crc32 crc32;
								  //         // crc32.input(scratch_pad, 10);
								  //           // std::cout << "Stage 1 scratch pad CRC32: 0x" << std::hex << std::setw(8) << std::setfill('0') << crc32.result() << std::endl;
								  //           }
								  //
								  //
								  //

								}

void xel_xel_stage1(const uint8_t *input, size_t input_len, uint8_t scratch_pad[XEL_OUTPUT_SIZE])
{
	uint8_t key[XEL_CHUNK_SIZE * XEL_CHUNKS] = {0};
	uint8_t input_hash[XEL_HASH_SIZE];
	uint8_t buffer[XEL_CHUNK_SIZE * 2];
	memcpy(key, input, XEL_INPUT_LEN);

	int j;
	LogPrintf("Key : ");
	for(j = 0; j < XEL_CHUNK_SIZE * XEL_CHUNKS; ++j)
        LogPrintf("%02x ", ((uint8_t*) key)[j]);
	LogPrintf(": \n ");


	blake3(input, XEL_INPUT_LEN, buffer);

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


static void aes_round(uint8_t *block, const uint8_t *key)
{
#if defined(__AES__) && defined(__x86_64__)
	  __m128i block_m128i = _mm_load_si128((__m128i *)block);
	    __m128i key_m128i = _mm_load_si128((__m128i *)key);
	      __m128i result = _mm_aesenc_si128(block_m128i, key_m128i);
	        _mm_store_si128((__m128i *)block, result);
#elif defined(__aarch64__)
		  uint8x16_t blck = vld1q_u8(block);
		    uint8x16_t ky = vld1q_u8(key);
		     // This magic sauce is from here: https://blog.michaelbrase.com/2018/06/04/optimizing-x86-aes-intrinsics-on-armv8-a/
		         uint8x16_t rslt = vaesmcq_u8(vaeseq_u8(blck, (uint8x16_t){})) ^ ky;
		           vst1q_u8(block, rslt);
		           #else
		             printf("Unsupported AES\n");
		             #endif

}
		      






void xel_stage3(uint64_t *scratch)
{
	uint64_t *mem_buffer_a = scratch;
	uint64_t *mem_buffer_b = &scratch[XEL_BUFSIZE];

	uint64_t addr_a = mem_buffer_b[XEL_BUFSIZE - 1];
	uint64_t addr_b = mem_buffer_a[XEL_BUFSIZE - 1] >> 32;
	uint32_t r = 0;
	const uint8_t key[17] = "xelishash-pow-v2";

	for (uint32_t i = 0; i < XEL_ITERS; i++)
	{
		uint64_t mem_a = mem_buffer_a[addr_a % XEL_BUFSIZE];
		uint64_t mem_b = mem_buffer_b[addr_b % XEL_BUFSIZE];

		uint8_t block[16];
		uint64_to_le_bytes(mem_b, block);
		uint64_to_le_bytes(mem_a, block + 8);
		aes_round(block, key);

		uint64_t hash1 = le_bytes_to_uint64(block);
		uint64_t hash2 = mem_a ^ mem_b;
		uint64_t result = ~(hash1 ^ hash2);

		for (uint32_t j = 0; j < XEL_BUFSIZE; j++)
		{
			uint64_t a = mem_buffer_a[result % XEL_BUFSIZE];
			uint64_t b = mem_buffer_b[~XEL_ROTR(result, r) % XEL_BUFSIZE];
			uint64_t c = (r < XEL_BUFSIZE) ? mem_buffer_a[r] : mem_buffer_b[r - XEL_BUFSIZE];
			r = (r < XEL_MEMSIZE - 1) ? r + 1 : 0;

			uint64_t v;
			__uint128_t t1, t2;
			switch (XEL_ROTL(result, (uint32_t)c) & 0xf)
			{
			case 0:
				v = XEL_ROTL(c, i * j) ^ b;
				break;
			case 1:
				v = XEL_ROTR(c, i * j) ^ a;
				break;
			case 2:
				v = a ^ b ^ c;
				break;
			case 3:
				v = ((a + b) * c);
				break;
			case 4:
				v = ((b - c) * a);
				break;
			case 5:
				v = (c - a + b);
				break;
			case 6:
				v = (a - b + c);
				break;
			case 7:
				v = (b * c + a);
				break;
			case 8:
				v = (c * a + b);
				break;
			case 9:
				v = (a * b * c);
				break;
			case 10:
			{
				t1 = combine_uint64(a, b);
				uint64_t t2 = c | 1;
				v = t1 % t2;
			}
			break;
			case 11:
			{
				t1 = combine_uint64(b, c);
				t2 = combine_uint64(XEL_ROTL(result, r), a | 2);
				v = (t2 > t1) ? c : t1 % t2;
			}
			break;
			case 12:
				v = udiv(c, a, b | 4);
				break;
			case 13:
			{
				t1 = combine_uint64(XEL_ROTL(result, r), b);
				t2 = combine_uint64(a, c | 8);
				v = (t1 > t2) ? t1 / t2 : a ^ b;
			}
			break;
			case 14:
			{
				t1 = combine_uint64(b, a);
				uint64_t t2 = c;
				v = (t1 * t2) >> 64;
			}
			break;
			case 15:
			{
				t1 = combine_uint64(a, c);
				t2 = combine_uint64(XEL_ROTR(result, r), b);
				v = (t1 * t2) >> 64;
			}
			break;
			}
			result = XEL_ROTL(result ^ v, 1);

			uint64_t t = mem_buffer_a[XEL_BUFSIZE - j - 1] ^ result;
			mem_buffer_a[XEL_BUFSIZE - j - 1] = t;
			mem_buffer_b[j] ^= XEL_ROTR(t, result);
		}
		addr_a = result;
		addr_b = xel_isqrt(result);
	}
}




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
void xelis_hash_v2(const void* data, size_t len, const uint256 PrevBlockHash, uint8_t hashResult[XEL_HASHSIZE])
{
			static uint8_t pblank[1];

			char buf[len];
			// char buf[8192];
			// LogPrintf("XELV2: Length is   %d\n",len);
			memcpy(buf, data, len);
			buf[len] = '\0';
			int j;
			/*
			LogPrintf("For loop: ");
			for(j = 0; j < len; ++j)
				  LogPrintf("%02x ", ((uint8_t*) data)[j]);
			LogPrintf(": \n ");
			LogPrintf("J Got to %d \n ",j);
			*/

			uint8_t dest_hash[len];
			std::memcpy(dest_hash, &buf, len);

			uint64_t *scratch = (uint64_t *)calloc(XEL_MEMSIZE, sizeof(uint64_t));
			uint8_t *scratch_uint8 = (uint8_t *)scratch;

			uint8_t scratch_pad[XEL_OUTPUT_SIZE];
			xel_stage_1(dest_hash, scratch, len);
			/*
			LogPrintf("Stage1 : ");
			for(j = 0; j < sizeof(scratch_uint8); ++j)
				  LogPrintf("%02x ", ((uint8_t*) scratch_uint8)[j]);
			LogPrintf(": \n ");
			*/
			xel_stage_3(scratch);
			blake3((uint8_t*)scratch, XEL_OUTPUT_SIZE, hashResult);
			return;

}
template<typename T1>
void pre_xelis_hash_v2(const T1 pbegin, const T1 pend, const uint256 PrevBlockHash, uint8_t hash_result[XEL_HASHSIZE]) {
	static unsigned char pblank[1];
	if(pbegin == pend) {
			LogPrintf("pre_xelis_hash_v2: pbegin == pend\n");
	}
	xelis_hash_v2((pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]), PrevBlockHash, hash_result);
	return;
}



uint256 CBlockHeader::GetHash() const
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
           LogPrintf("CBlockHeader::xelis_hash %s\n",res.ToString());
	   return res;
    }
    PePeHash = pepe_hash(BEGIN(nVersion), END(nNonce), hashPrevBlock);
    // LogPrintf("CBlockHeader::pepe_hash - %s \n",PePeHash.ToString());
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
