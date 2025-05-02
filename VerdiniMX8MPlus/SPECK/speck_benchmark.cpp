// Speck-64/128 CBC benchmark using Simon_Speck_Ciphers repo implementation
// Compile (ARM64):
//   aarch64-linux-gnu-g++ speck_benchmark.cpp speck.c -I. -o speck_bench_cbc_arm64

#include <chrono>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <cstring>
#include <sys/resource.h>

// Work around mode_t conflict from sys/types.h
#ifdef mode_t
#undef mode_t
#endif

#include "cipher_constants.h"
#include "speck.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <iterations> <plaintext>\n";
        return 1;
    }
    size_t iterations = std::stoul(argv[1]);
    std::string plain = argv[2];

    const size_t BLOCK_SIZE = 8; // bytes per block
    const size_t KEY_SIZE = 16;  // bytes (128-bit key)

    // Pad plaintext
    size_t data_len = plain.size();
    size_t pad_len = ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    std::vector<uint8_t> pt(pad_len, 0);
    memcpy(pt.data(), plain.data(), data_len);
    size_t blocks = pad_len / BLOCK_SIZE;

    std::vector<uint8_t> ct(pad_len), dt(pad_len);

    // Example key and IV
    uint8_t key[KEY_SIZE];
    for (size_t i = 0; i < KEY_SIZE; ++i)
        key[i] = static_cast<uint8_t>(i);
    uint8_t iv[BLOCK_SIZE] = {0};

    // Estimate algorithm's memory footprint
    size_t cipher_struct_size = sizeof(SimSpk_Cipher); // Size of cipher object
    size_t key_size = KEY_SIZE;                        // Key buffer
    size_t iv_size = BLOCK_SIZE;                       // IV buffer
    size_t pt_size = pad_len;                          // Plaintext buffer
    size_t ct_size = pad_len;                          // Ciphertext buffer
    size_t dt_size = pad_len;                          // Decrypted text buffer
    size_t total_algo_memory = cipher_struct_size + key_size + iv_size + pt_size + ct_size + dt_size;

    // Measure CPU time and memory for encryption
    struct rusage ru_start, ru_enc, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);
    auto t0 = std::chrono::high_resolution_clock::now();

    // Encryption benchmark
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher cipher = {};
        std::cout << "Before Speck_Init (encrypt): cipher.block_size = " << (int)cipher.block_size << "\n";
        int init_result = Speck_Init(&cipher, cfg_128_64, CBC, key, iv, nullptr);
        std::cout << "Speck_Init (encrypt) returned: " << init_result << "\n";
        std::cout << "After Speck_Init (encrypt): cipher.block_size = " << (int)cipher.block_size << "\n";
        if (init_result != 0)
        {
            std::cerr << "Speck_Init failed with return value: " << init_result << "\n";
            return 1;
        }
        for (size_t b = 0; b < blocks; ++b)
        {
            Speck_Encrypt(cipher, pt.data() + b * BLOCK_SIZE, ct.data() + b * BLOCK_SIZE);
        }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &ru_enc);

    // Decryption benchmark
    auto t2 = std::chrono::high_resolution_clock::now();
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher cipher = {};
        std::cout << "Before Speck_Init (decrypt): cipher.block_size = " << (int)cipher.block_size << "\n";
        int init_result = Speck_Init(&cipher, cfg_128_64, CBC, key, iv, nullptr);
        std::cout << "Speck_Init (decrypt) returned: " << init_result << "\n";
        std::cout << "After Speck_Init (decrypt): cipher.block_size = " << (int)cipher.block_size << "\n";
        if (init_result != 0)
        {
            std::cerr << "Speck_Init failed with return value: " << init_result << "\n";
            return 1;
        }
        for (size_t b = 0; b < blocks; ++b)
        {
            Speck_Decrypt(cipher, ct.data() + b * BLOCK_SIZE, dt.data() + b * BLOCK_SIZE);
        }
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &ru_end);

    // Calculate metrics
    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double dec_us = std::chrono::duration<double, std::micro>(t3 - t2).count();
    double avg_enc = enc_us / iterations;
    double avg_dec = dec_us / iterations;
    double tp_enc = (iterations * pad_len) / (enc_us / 1e6);
    double tp_dec = (iterations * pad_len) / (dec_us / 1e6);

    // CPU usage for encryption
    double wall_enc_s = std::chrono::duration<double>(t1 - t0).count();
    double cpu_start = ru_start.ru_utime.tv_sec + ru_start.ru_utime.tv_usec / 1e6 + ru_start.ru_stime.tv_sec + ru_start.ru_stime.tv_usec / 1e6;
    double cpu_enc = ru_enc.ru_utime.tv_sec + ru_enc.ru_utime.tv_usec / 1e6 + ru_enc.ru_stime.tv_sec + ru_enc.ru_stime.tv_usec / 1e6;
    double cpu_usage_enc = ((cpu_enc - cpu_start) / wall_enc_s) * 100.0;

    // Memory usage
    long ram_enc_peak = ru_enc.ru_maxrss * 1024; // Convert KB to bytes
    long ram_dec_peak = ru_end.ru_maxrss * 1024; // Convert KB to bytes

    // Output metrics
    std::cout << "Enc=" << enc_us << " us\n"
              << "Dec=" << dec_us << " us\n"
              << "AvgEnc=" << avg_enc << " us\n"
              << "AvgDec=" << avg_dec << " us\n"
              << "ThroughputEnc=" << tp_enc << " B/s\n"
              << "ThroughputDec=" << tp_dec << " B/s\n"
              << "CPUUsageEnc=" << cpu_usage_enc << "%\n"
              << "PeakRAMEnc=" << ram_enc_peak << " bytes\n"
              << "PeakRAMDec=" << ram_dec_peak << " bytes\n"
              << "EstimatedAlgoRAM=" << total_algo_memory << " bytes\n";

    return 0;
}