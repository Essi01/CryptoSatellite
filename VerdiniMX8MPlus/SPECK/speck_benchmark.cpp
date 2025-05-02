// speck_benchmark.cpp
// Speck-64/128 CBC benchmark: run N iterations encrypting a given plaintext string
// Compile with:
//   g++ -O3 speck_benchmark.cpp -o speck_bench_cbc
// Usage:
//   ./speck_bench_cbc <iterations> "<plaintext>"

#include <chrono>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#define ROR64(x, r) _rotr64(x, r)
#define ROL64(x, r) _rotl64(x, r)
#else
#define ROR64(x, r) ((uint64_t)(x) >> (r) | (uint64_t)(x) << (64 - (r)))
#define ROL64(x, r) ((uint64_t)(x) << (r) | (uint64_t)(x) >> (64 - (r)))
#endif
#define ROUND(x, y, k)   \
    do                   \
    {                    \
        x = ROR64(x, 8); \
        x = x + y;       \
        x ^= k;          \
        y = ROL64(y, 3); \
        y ^= x;          \
    } while (0)

static inline void speck64_128_encrypt_block(const uint64_t pt[2], uint64_t ct[2], const uint64_t key[2])
{
    uint64_t x = pt[1], y = pt[0];
    uint64_t k0 = key[0], k1 = key[1];
    ROUND(x, y, k0);
    for (int i = 0; i < 31; ++i)
    {
        // key schedule on-the-fly
        k1 = ROR64(k1, 8);
        k1 = k1 + k0;
        k1 ^= (uint64_t)i;
        k0 = ROL64(k0, 3);
        k0 ^= k1;
        ROUND(x, y, k0);
    }
    ct[0] = y;
    ct[1] = x;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <iterations> \"<plaintext>\"\n";
        return 1;
    }

    size_t iterations = std::stoul(argv[1]);
    std::string plaintext = argv[2];

    const size_t WORD_BYTES = 8;
    const size_t BYTES_PER_BLOCK = WORD_BYTES * 2; // 16 bytes per block

    // Prepare plaintext buffer and pad
    size_t data_len = plaintext.size();
    size_t pad_len = ((data_len + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK) * BYTES_PER_BLOCK;
    std::vector<uint8_t> pt_bytes(pad_len, 0);
    memcpy(pt_bytes.data(), plaintext.data(), data_len);
    size_t blocks = pad_len / BYTES_PER_BLOCK;

    // Convert to 64-bit words
    std::vector<uint64_t> pt_words(blocks * 2), ct_words(blocks * 2);
    for (size_t i = 0; i < blocks; ++i)
    {
        uint64_t w0 = 0, w1 = 0;
        for (size_t b = 0; b < WORD_BYTES; ++b)
        {
            w0 |= uint64_t(pt_bytes[i * BYTES_PER_BLOCK + b]) << (8 * b);
            w1 |= uint64_t(pt_bytes[i * BYTES_PER_BLOCK + WORD_BYTES + b]) << (8 * b);
        }
        pt_words[2 * i] = w0;
        pt_words[2 * i + 1] = w1;
    }

    // Key and IV
    uint64_t key[2] = {0x8899AABBCCDDEEFFULL, 0x0011223344556677ULL};
    uint64_t iv = 0;

    // Warm-up
    for (size_t it = 0; it < iterations; ++it)
    {
        uint64_t prev = iv;
        for (size_t i = 0; i < blocks; ++i)
        {
            uint64_t in_blk[2] = {pt_words[2 * i] ^ prev, pt_words[2 * i + 1]};
            uint64_t out_blk[2];
            speck64_128_encrypt_block(in_blk, out_blk, key);
            prev = out_blk[0];
        }
    }

    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t it = 0; it < iterations; ++it)
    {
        uint64_t prev = iv;
        for (size_t i = 0; i < blocks; ++i)
        {
            uint64_t in_blk[2] = {pt_words[2 * i] ^ prev, pt_words[2 * i + 1]};
            uint64_t out_blk[2];
            speck64_128_encrypt_block(in_blk, out_blk, key);
            ct_words[2 * i] = out_blk[0];
            ct_words[2 * i + 1] = out_blk[1];
            prev = out_blk[0];
        }
    }
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> elapsed = end - start;
    double seconds = elapsed.count();

    double latency_us = (seconds * 1e6) / iterations;
    double throughput_kBps = (iterations * pad_len) / 1024.0 / seconds;

    std::cout << "Iterations: " << iterations << "\n";
    std::cout << "Message size: " << data_len << " bytes (" << blocks << " blocks)\n";
    std::cout << "Latency: " << latency_us << " us/enc\n";
    std::cout << "Throughput: " << throughput_kBps << " kB/s\n";
    return 0;
}
