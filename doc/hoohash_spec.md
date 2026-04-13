# HoohashV110 PoW Specification (PEPEW family): header preimage, matrix seeding, and hash encoding

Date: 2026-02-24  
Status: Practical interop specification for miners, pools, and validators.

This document specifies the **byte-level preimage** and **algorithm steps** for `hoohashv110` Proof-of-Work as used in PEPEW-style networks, plus the required conventions for representing the resulting 256-bit hash in RPC / Stratum contexts.

It is written to be implementation-agnostic: C/C++, Rust, Go, JS, etc. should all be able to interoperate if they follow this spec.

NB - Hoohash is especially sensitive to FP64 variances, and should NOT be assumed to be determinstic beyond the reference C implementation without extensive vector testing.

---

## 1. Scope

This spec defines:

1. The PoW **preimage**: exactly which bytes are hashed (an 80-byte block header).
2. The `hoohashv110` function: how BLAKE3, matrix seed masking, matrix generation, nonce handling, and final multiplication combine.
3. The **digest encoding** rules: how to interpret the 32-byte output, and how to serialize/print it for:
   - consensus comparisons (target check),
   - daemon RPC calls (e.g., `getblock <hash>`),
   - Stratum and miner UI display.

This spec does *not* define:
- coinbase construction,
- merkle tree construction beyond producing a standard 32-byte merkle root,
- Stratum job field formats (except insofar as they must produce the same 80-byte header preimage).

---

## 2. PoW preimage: the 80-byte block header

`hoohashv110` hashes exactly the standard Bitcoin-derived block header:

| Field | Size | Offset | Encoding |
|------:|-----:|-------:|----------|
| nVersion | 4 | 0 | uint32 little-endian |
| hashPrevBlock | 32 | 4 | 32 raw bytes (as in the serialized header) |
| hashMerkleRoot | 32 | 36 | 32 raw bytes (as in the serialized header) |
| nTime | 4 | 68 | uint32 little-endian |
| nBits | 4 | 72 | uint32 little-endian (compact target) |
| nNonce | 4 | 76 | uint32 little-endian |

Let `hdr80` be the concatenation of these fields, total length 80 bytes.

### 2.1 Normative requirements
- **MUST** hash exactly 80 bytes. If an implementation is given a different length, it **MUST** reject (or deterministically return an error value); it must not hash a variable-length input.
- `nNonce` is defined as the 4 bytes at offsets `[76..79]` in little-endian order.

---

## 3. HoohashV110 function definition

### 3.1 Inputs and outputs
**Input:** `hdr80` (80 bytes)  
**Output:** `digest` (32 bytes)

All arrays are byte arrays unless otherwise stated.

### 3.2 Primitives
- `BLAKE3(x)` means BLAKE3 hash of `x`, output 32 bytes.
- `read_u32_le(b[0..3])` reads a 32-bit unsigned integer from 4 bytes little-endian.
- `generate_matrix(seed32) -> mat[64][64]` deterministically produces a 64×64 matrix of IEEE-754 double values from the 32-byte seed.
- `matrix_mult(mat, firstPass32, nonce_u32) -> digest32` deterministically produces a 32-byte digest from the matrix, the first-pass hash, and the nonce.

> Note: `generate_matrix` and `matrix_mult` are consensus-critical. All implementers must use the same algorithm and constants as the reference implementation for their network. This spec describes the *composition* and the nonce/masking rules; it assumes those two functions are defined elsewhere in the network’s reference code.

### 3.3 Algorithm steps (normative)

Given `hdr80`:

1) **Nonce-dependent first pass**
- `firstPass = BLAKE3(hdr80)`

2) **Nonce-independent matrix seed**
- Construct `hdr80_masked` as a copy of `hdr80`
- Set bytes `hdr80_masked[76..79] = 0x00 0x00 0x00 0x00`
- `matrixSeed = BLAKE3(hdr80_masked)`

3) **Matrix generation**
- `mat = generate_matrix(matrixSeed)`

4) **Nonce extraction**
- `nonce = read_u32_le(hdr80[76..79])`  (a 32-bit value; may be widened to 64-bit in implementations)

5) **Final PoW**
- `digest = matrix_mult(mat, firstPass, nonce)`

Return `digest` (32 bytes).

### 3.4 Rationale (informative)
- The key consensus rule is that the per-block matrix is constant for a given header template and does **not** change with nonce. This is enforced by masking the nonce bytes for the matrix seed.
- The nonce still influences the final output via `matrix_mult`.

---

## 4. Target check (consensus comparison)

### 4.1 Compact target decoding
Decode `nBits` (compact format) into a 256-bit target integer `T` using the standard Bitcoin compact encoding rules.

### 4.2 Comparing hash to target
Consensus validity requires:

- Interpret `digest` as a 256-bit unsigned integer `H` in the network-defined byte order.
- The block is valid if: `H <= T`.

**Important:** The byte order used to interpret `digest` into integer form is consensus-critical and must match the daemon/reference implementation for the network.

In many Bitcoin-derived systems, internal `uint256` comparisons treat the underlying 32 bytes as little-endian “limbs” even if the displayed hex is reversed. However, some PoW implementations treat the digest bytes as big-endian.

**Therefore:**
- Implementers **MUST** follow the reference node’s interpretation for `hoohashv110` on that network.
- Pools/miners should validate by matching a known-answer test vector from the daemon (see §7).

---

## 5. Hash string encodings (RPC vs display)

The `digest` is 32 bytes. Different systems *print* or *transmit* a 64-hex-character “hash string” in different byte orders.

Define:

- `RAW_HEX = hex(digest)` (byte order as returned by `hoohashv110`)
- `REV_HEX = hex(reverse_bytes(digest))`

### 5.1 Canonical block id in RPC
For many daemon RPCs (e.g., `getblock <hash>`), the expected `<hash>` string is a specific encoding (either `RAW_HEX` or `REV_HEX`) depending on the node’s convention.

**Normative guidance:**
- Miners/pools **MUST** determine which form the daemon expects by checking the reference node behavior:
  - If the daemon logs a new best block as a hex string `X`, then `getblock X` must succeed.
  - The string `X` is the daemon’s canonical RPC encoding.

### 5.2 Miner/pool “display hash”
Some mining software displays `REV_HEX` because it matches the common Bitcoin “reversed hex” block hash presentation.

This is a UI choice and does not change consensus; however, confusing RPC hash vs display hash is a common source of “Block not found” errors.

---

## 6. Stratum interoperability (informative but practical)

Stratum does not inherently define “the 80 bytes” — it defines fields from which miners construct work. To interoperate:

- Pool and miner must agree on how Stratum job fields are converted into the consensus `hdr80`.
- The definitive test is: **the miner’s `hdr80` must equal the node’s serialized header bytes** for the candidate block.

Best practice:
- Provide (or log) `hdr80` as a hex string in both pool and miner for cross-checking.
- Validate that `hoohashv110(hdr80)` matches the reference node for the same header.

---

## 7. Known Answer Tests (KAT) (strongly recommended)

Because `hoohashv110` uses floating-point matrix math, differences in:
- compiler flags (FMA, fp-contract),
- platform FP behavior,
- accidental source drift,
- or wrong byte order

can produce silent mismatches.

Recommended C compile flags:

```
-fno-fast-math -ffp-contract=off -fexcess-precision=standard -mno-fma -mno-fma4

```

Additional X64 flags that may be required, especially on Windows to avoid use of the x87 FPU
```
 -mfpmath=sse -msse2
```

Every miner/pool implementation should include a KAT (samples are provided in src/crypto/hoohash):

A KAT vector contains:
- `hdr80_hex` (160 hex chars)
- `expected_digest_hex` in the daemon’s **canonical encoding** (either RAW_HEX or REV_HEX; specify which)

Validation:
- Compute `digest = hoohashv110(hdr80)`
- Compare against expected bytes/hex.

If the KAT fails, do not mine.

---

## 8. Reference Implementation

https://github.com/HoosatNetwork/hoohash

Which is utilised in PEPEPOW as:

```text
#define HOOHASH_HASH_SIZE 32
void hoohashv110(const void* data, size_t len, uint8_t output[HOOHASH_HASH_SIZE])
{
    if (len != 80) {
        return;
    }

    blake3_hasher hasher;
    uint8_t firstPass[HOOHASH_HASH_SIZE];
    uint8_t matrixSeed[HOOHASH_HASH_SIZE];
    double mat[64][64];

    const uint8_t *hdr = (const uint8_t *)data;

    /* 1) Nonce-dependent first pass: BLAKE3(full header) */
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, hdr, 80);
    blake3_hasher_finalize(&hasher, firstPass, HOOHASH_HASH_SIZE);

    /* 2) Nonce-independent matrix seed: BLAKE3(header with nonce bytes zeroed) */
    uint8_t hdr_masked[80];
    memcpy(hdr_masked, hdr, 80);
    hdr_masked[76] = 0;
    hdr_masked[77] = 0;
    hdr_masked[78] = 0;
    hdr_masked[79] = 0;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, hdr_masked, 80);
    blake3_hasher_finalize(&hasher, matrixSeed, HOOHASH_HASH_SIZE);

    /* 3) Matrix is constant for all nonces for this header template */
    generateHoohashMatrix(matrixSeed, mat);

    /* 4) Read the real nonce from the real header (little-endian uint32 at offset 76) */
    const uint64_t nonce = (uint64_t)read_uint32_le(hdr + 76);

    /* 5) Final PoW */
    HoohashMatrixMultiplication(mat, firstPass, output, nonce);
}
```


---

## 9. Common failure modes

1) **Hashing the wrong bytes**
- e.g., hashing a Stratum “job blob” that is not the true 80-byte header.

2) **Nonce masking done incorrectly**
- wrong offset (must be bytes 76–79),
- masking the wrong endianness,
- masking in the wrong stage (must only affect matrix seed, not first pass).

3) **RPC hash string endianness confusion**
- `getblock` expects canonical encoding; display encoding may differ.

4) **Floating point non-determinism**
- mismatched compiler flags producing different results for matrix multiplication.

---

## 10. Conformance checklist

An implementation conforms if:

- It hashes exactly the 80-byte header format in §2.
- It computes `firstPass` and `matrixSeed` per §3 (nonce masking only for matrixSeed).
- It uses reference-consistent `generate_matrix` and `matrix_mult`.
- It matches at least one published KAT vector from the reference daemon.
- It uses the daemon’s canonical hash string encoding for RPC operations.

## 11. Core Node Reference

See

- Al files in src/crypto/hoohash/
- src/primitives/block.cpp
- 
