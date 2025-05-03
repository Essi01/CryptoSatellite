#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Enable GNU extensions for CPU_SET
#endif

#include <chrono>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <string.h> // For strerror
#include <thread>
#include <atomic>
#include <mutex>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h> // For CPU_ZERO, CPU_SET
#include <errno.h> // For errno
#include <fstream>

#include "cipher_constants.h"
#include "speck.h"

// INA219 settings (via hwmon)
static const char *HWMON_PATH = "/sys/class/hwmon/hwmon4"; // INA219 on Verdin iMX8M Plus

class INA219
{
    std::string power_path;

public:
    INA219(const char *hwmon_path)
    {
        power_path = std::string(hwmon_path) + "/power1_input";
        // Verify file exists
        std::ifstream f(power_path);
        if (!f.is_open())
        {
            std::cerr << "Cannot open " << power_path << ": " << strerror(errno) << "\n";
        }
    }

    bool begin()
    {
        // No initialization needed for hwmon; assume driver is configured
        std::ifstream f(power_path);
        return f.is_open();
    }

    float readPower_mW()
    {
        std::ifstream f(power_path);
        if (!f.is_open())
        {
            std::cerr << "Failed to read " << power_path << ": " << strerror(errno) << "\n";
            return 0;
        }
        std::string line;
        std::getline(f, line);
        try
        {
            // power1_input is in microwatts; convert to milliwatts
            return std::stof(line) / 1000.0f;
        }
        catch (...)
        {
            std::cerr << "Invalid power reading from " << power_path << "\n";
            return 0;
        }
    }
};

INA219 ina(HWMON_PATH);

// power-sampling control
std::atomic<bool> sampling{false};
std::vector<float> power_samples;
std::mutex samples_mtx;

// pin thread to specific core
void pin_to_core(int core_id)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(core_id, &cpus);
    pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
}

// power-sampling thread
void power_thread_fn()
{
    pin_to_core(1);
    while (sampling.load())
    {
        float p = ina.readPower_mW();
        {
            std::lock_guard<std::mutex> lk(samples_mtx);
            power_samples.push_back(p);
        }
        std::this_thread::sleep_for(std::chrono::microseconds(1200));
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <iterations> <plaintext>\n";
        return 1;
    }
    size_t iterations = std::stoul(argv[1]);
    std::string plain = argv[2];

    // init INA219
    if (!ina.begin())
    {
        std::cerr << "INA219 init failed\n";
        return 1;
    }

    // prepare data
    const size_t BLOCK_SIZE = 8, KEY_SIZE = 16;
    size_t data_len = plain.size(),
           pad_len = ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    std::vector<uint8_t> pt(pad_len, 0), ct(pad_len), dt(pad_len);
    memcpy(pt.data(), plain.data(), data_len);
    uint8_t key[KEY_SIZE], iv[BLOCK_SIZE] = {0};
    for (size_t i = 0; i < KEY_SIZE; i++)
        key[i] = uint8_t(i);

    // start power thread
    sampling.store(true);
    std::thread pwr_thread(power_thread_fn);

    // capture baseline
    struct rusage ru_start, ru_enc, ru_end;
    getrusage(RUSAGE_SELF, &ru_start);
    auto t0 = std::chrono::high_resolution_clock::now();

    // encryption
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher c{};
        int r = Speck_Init(&c, cfg_128_64, CBC, key, iv, nullptr);
        if (r)
        {
            sampling.store(false);
            pwr_thread.join();
            return 1;
        }
        for (size_t b = 0; b < pad_len / BLOCK_SIZE; ++b)
            Speck_Encrypt(c, pt.data() + b * BLOCK_SIZE, ct.data() + b * BLOCK_SIZE);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &ru_enc);

    // decryption
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher c{};
        int r = Speck_Init(&c, cfg_128_64, CBC, key, iv, nullptr);
        if (r)
        {
            sampling.store(false);
            pwr_thread.join();
            return 1;
        }
        for (size_t b = 0; b < pad_len / BLOCK_SIZE; ++b)
            Speck_Decrypt(c, ct.data() + b * BLOCK_SIZE, dt.data() + b * BLOCK_SIZE);
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &ru_end);

    // stop sampling
    sampling.store(false);
    pwr_thread.join();

    // compute power stats
    double sum = 0;
    {
        std::lock_guard<std::mutex> lk(samples_mtx);
        for (float p : power_samples)
            sum += p;
    }
    double avg_p = power_samples.empty() ? 0 : sum / power_samples.size();
    double dur_s = std::chrono::duration<double>(t3 - t0).count();
    double e_mJ = avg_p * dur_s;

    // timing
    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double dec_us = std::chrono::duration<double, std::micro>(t3 - t1).count();
    double avg_e = enc_us / iterations;
    double avg_d = dec_us / iterations;
    double tp_e = (iterations * pad_len) / (enc_us / 1e6);
    double tp_d = (iterations * pad_len) / (dec_us / 1e6);

    long ram_e = ru_enc.ru_maxrss * 1024;
    long ram_d = ru_end.ru_maxrss * 1024;

    std::cout
        << "\nEnc=" << enc_us << " us\n"
        << "Dec=" << dec_us << " us\n"
        << "AvgEnc=" << avg_e << " us\n"
        << "AvgDec=" << avg_d << " us\n"
        << "ThroughputEnc=" << tp_e << " B/s\n"
        << "ThroughputDec=" << tp_d << " B/s\n"
        << "PeakRAMEnc=" << ram_e << " bytes\n"
        << "PeakRAMDec=" << ram_d << " bytes\n\n"
        << "PowerSamples=" << power_samples.size() << "\n"
        << "AvgPower=" << avg_p << " mW\n"
        << "Energy=" << e_mJ << " mJ\n";

    return 0;
}