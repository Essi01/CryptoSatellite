// speck_benchmark.cpp
// Speck-64/128 CBC benchmark: runs N iterations encrypting/decrypting a plaintext string
// Detailed report similar to ChaCha20 example

// Cross-compile and deploy:
// 1) On your PC (WSL/Ubuntu), install ARM64 toolchain:
//      sudo apt update && sudo apt install g++-aarch64-linux-gnu
// 2) Build ARM64 binary:
//      aarch64-linux-gnu-g++ -O3 speck_benchmark.cpp -o speck_bench_cbc_arm64
// 3) Copy to Toradex:
//      scp speck_bench_cbc_arm64 root@128.39.202.99:/home/root/
// 4) On Toradex, set executable:
//      ssh root@128.39.202.99 chmod +x /home/root/speck_bench_cbc_arm64
// 5) Run benchmark:
//      ssh root@128.39.202.99 "/home/root/speck_bench_cbc_arm64 5000 \"SAT-TEST-1234: Secure Transmission OK\""

// Native build on device:
//   g++ -O3 speck_benchmark.cpp -o speck_bench_cbc
//   chmod +x speck_bench_cbc
//   ./speck_bench_cbc <iterations> "<plaintext>"

// Usage:
//   1) Transfer source to the ARM device and compile there:
//        g++ -O3 speck_benchmark.cpp -o speck_bench_cbc
//        chmod +x speck_bench_cbc
//   2) Run on device:
//        ./speck_bench_cbc <iterations> "<plaintext>"
//   If you cross-compile locally, ensure you copy the ARM64 binary, not the .cpp file.
//   ./speck_bench_cbc <iterations> "<plaintext>"



// speck_benchmark_repo.cpp
// Speck-64/128 CBC benchmark using Simon_Speck_Ciphers repo implementation
// Compile (ARM64):
//   aarch64-linux-gnu-g++ -O3 speck_benchmark_repo.cpp speck.c cipher_constants.c -I. -o speck_bench_cbc_arm64
// Deploy and run as needed
// Structured output with CPU usage for encryption with CPU usage for encryption
// Cross-compile for ARM64 and deploy as needed

// Compile (ARM64):
//   aarch64-linux-gnu-g++ -O3 speck_benchmark_repo.cpp speck.c cipher_constants.c -I. -o speck_bench_cbc_arm64