// aes_benchmark.cpp
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <random>
#include <climits>
#include <sys/stat.h>
#include "aes_core.h"

using namespace std;
using namespace std::chrono;

// get microseconds since epoch
static uint64_t micros64()
{
    return duration_cast<microseconds>(
               steady_clock::now().time_since_epoch())
        .count();
}

// safe subtraction across wrap
static uint64_t safeTimeDiff(uint64_t start, uint64_t end)
{
    return (end >= start)
               ? (end - start)
               : (UINT64_MAX - start + end + 1);
}

// fill IV with random bytes
static void generateIV(unsigned char *iv, size_t size)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < size; i++)
        iv[i] = static_cast<unsigned char>(dis(gen));
}

// PKCS#7 pad
static size_t padData(const char *in,
                      unsigned char *out,
                      size_t len,
                      size_t max_len)
{
    if (len >= max_len)
        return 0;
    size_t padded = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (padded > max_len)
        return 0;
    memcpy(out, in, len);
    unsigned char v = static_cast<unsigned char>(padded - len);
    for (size_t i = len; i < padded; i++)
        out[i] = v;
    return padded;
}

// print VmRSS/VmPeak and size of this executable
static void printMemAndRom(const char *label)
{
    ifstream f("/proc/self/status");
    string line;
    int vmrss = 0, vmpeak = 0;
    while (getline(f, line))
    {
        if (line.rfind("VmRSS:", 0) == 0)
            vmrss = stoi(line.substr(6));
        if (line.rfind("VmPeak:", 0) == 0)
            vmpeak = stoi(line.substr(7));
    }
    cout << "MEMORY [" << label << "]: "
         << "VmRSS " << vmrss << " kB, "
         << "VmPeak " << vmpeak << " kB\n";
    struct stat st;
    if (stat("/proc/self/exe", &st) == 0)
    {
        cout << "ROM/FLASH: " << (st.st_size / 1024) << " kB\n";
    }
    cout << "\n";
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cerr << "Usage: " << argv[0]
             << " <repeats> \"text to encrypt\"\n";
        return 1;
    }
    long repeats = atol(argv[1]);
    if (repeats <= 0)
    {
        cerr << "Error: Repeats must be positive\n";
        return 1;
    }
    string text = argv[2];
    if (text.empty())
    {
        cerr << "Error: Input text cannot be empty\n";
        return 1;
    }

    // ——— HEADER + MEMORY/ROM ———
    cout << "Ny testing AES-CBC\n";
    cout << "1.  REPEAT " << repeats
         << " \"" << text << "\"\n";
    printMemAndRom("Before Benchmark");

    // prepare buffers
    const size_t MAX_BUF = 256;
    unsigned char padded[MAX_BUF] = {0},
                  encrypted[MAX_BUF + IV_SIZE] = {0},
                  decrypted[MAX_BUF] = {0};
    size_t in_len = text.size();
    size_t pad_len = padData(text.c_str(),
                             padded,
                             in_len,
                             MAX_BUF);
    if (!pad_len)
    {
        cerr << "Error: padding failed or input too large\n";
        return 1;
    }

    AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key);

    // start timers
    auto wall0 = steady_clock::now();
    clock_t cpu0 = clock();

    // ——— BENCHMARK STARTED ———
    cout << "==========================================\n"
         << "         BENCHMARK STARTED               \n"
         << "==========================================\n";
    cout << "Starting AES-CBC benchmark with " << repeats
         << " repetitions...\n"
         << "Input: \"" << text << "\" (" << in_len
         << " bytes, padded to " << pad_len << " bytes)\n\n"
         << "Starting crypto benchmark processing...\n";

    uint64_t total_e = 0, total_d = 0;
    for (long i = 0; i < repeats; i++)
    {
        if ((i & 0x3FF) == 0)
            cout << '.';

        unsigned char iv[IV_SIZE], iv_e[IV_SIZE], iv_d[IV_SIZE];
        generateIV(iv, IV_SIZE);
        memcpy(iv_e, iv, IV_SIZE);
        memcpy(iv_d, iv, IV_SIZE);

        memcpy(encrypted, iv_e, IV_SIZE);
        memcpy(encrypted + IV_SIZE, padded, pad_len);

        uint64_t t0 = micros64();
        AES_CBC_encrypt(&ctx,
                        iv_e,
                        encrypted + IV_SIZE,
                        static_cast<uint32_t>(pad_len));
        uint64_t t1 = micros64();
        total_e += safeTimeDiff(t0, t1);

        memcpy(decrypted, encrypted + IV_SIZE, pad_len);
        uint64_t t2 = micros64();
        AES_CBC_decrypt(&ctx,
                        iv_d,
                        decrypted,
                        static_cast<uint32_t>(pad_len));
        uint64_t t3 = micros64();
        total_d += safeTimeDiff(t2, t3);
    }
    cout << "\n\n";

    // stop timers
    auto wall1 = steady_clock::now();
    clock_t cpu1 = clock();
    double wall_ms = duration_cast<milliseconds>(wall1 - wall0).count();
    double cpu_ms = double(cpu1 - cpu0) / CLOCKS_PER_SEC * 1000.0;
    double cpu_pct = cpu_ms / wall_ms * 100.0;

    float avgE = total_e / float(repeats);
    float avgD = total_d / float(repeats);

    // ——— RESULTS ———
    cout << "==========================================\n"
         << "         BENCHMARK RESULTS               \n"
         << "==========================================\n";
    cout << "Input text: \"" << text << "\" (" << in_len
         << " bytes, padded to " << pad_len << " bytes)\n";
    cout << "Total encrypt time: " << total_e << " µs\n";
    cout << "Total decrypt time: " << total_d << " µs\n";
    cout << "Total benchmark time: " << fixed
         << setprecision(0) << wall_ms << " ms\n";
    cout << "Actual CPU usage: " << fixed
         << setprecision(2) << cpu_pct << "%\n\n";

    cout << "Avg Encrypt Time: " << fixed
         << setprecision(2) << avgE << " µs\n";
    cout << "Avg Decrypt Time: " << fixed
         << setprecision(2) << avgD << " µs\n";
    cout << "Throughput Encrypt: " << fixed
         << setprecision(2)
         << (pad_len * 1e6f / avgE) << " bytes/s\n";
    cout << "Throughput Decrypt: " << fixed
         << setprecision(2)
         << (pad_len * 1e6f / avgD) << " bytes/s\n";
    cout << "Decrypted text: "
         << string(reinterpret_cast<char *>(decrypted),
                   in_len)
         << "\n";

    return 0;
}
