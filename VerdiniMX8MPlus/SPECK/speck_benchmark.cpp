#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Enable GNU extensions for CPU_SET
#endif
#define NDEBUG // Disable debug output in speck.c (if applicable)

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
#include <sstream>
#include <sys/stat.h> // For stat

#include "cipher_constants.h"
#include "speck.h"

// INA219 settings (via hwmon)
static const char *HWMON_PATH = "/sys/class/hwmon/hwmon4"; // INA219 on Verdin iMX8M Plus

class INA219
{
    std::string power_path, current_path;

public:
    INA219(const char *hwmon_path)
    {
        power_path = std::string(hwmon_path) + "/power1_input";
        current_path = std::string(hwmon_path) + "/curr1_input";
        // Verify files exist
        std::ifstream f_power(power_path);
        if (!f_power.is_open())
        {
            std::cerr << "Cannot open " << power_path << ": " << strerror(errno) << "\n";
        }
        std::ifstream f_current(current_path);
        if (!f_current.is_open())
        {
            std::cerr << "Cannot open " << current_path << ": " << strerror(errno) << "\n";
        }
    }

    bool begin()
    {
        // No initialization needed for hwmon; assume driver is configured
        std::ifstream f_power(power_path);
        std::ifstream f_current(current_path);
        return f_power.is_open() && f_current.is_open();
    }

    void readMeasurements(float &power_mW, float &current_mA)
    {
        // Read power
        std::ifstream f_power(power_path);
        if (!f_power.is_open())
        {
            std::cerr << "Failed to read " << power_path << ": " << strerror(errno) << "\n";
            power_mW = 0;
        }
        else
        {
            std::string line;
            std::getline(f_power, line);
            try
            {
                // power1_input is in microwatts; convert to milliwatts
                power_mW = std::stof(line) / 1000.0f;
            }
            catch (...)
            {
                std::cerr << "Invalid power reading from " << power_path << "\n";
                power_mW = 0;
            }
        }

        // Read current
        std::ifstream f_current(current_path);
        if (!f_current.is_open())
        {
            std::cerr << "Failed to read " << current_path << ": " << strerror(errno) << "\n";
            current_mA = 0;
        }
        else
        {
            std::string line;
            std::getline(f_current, line);
            try
            {
                // curr1_input is in milliamps
                current_mA = std::stof(line);
            }
            catch (...)
            {
                std::cerr << "Invalid current reading from " << current_path << "\n";
                current_mA = 0;
            }
        }
    }
};

INA219 ina(HWMON_PATH);

// power, current, and CPU sampling control
std::atomic<bool> sampling{false};
std::atomic<bool> cpu_sampling{false};
std::vector<float> power_samples, current_samples;
std::vector<float> cpu_usage_samples;
std::mutex samples_mtx;

// pin thread to specific core
void pin_to_core(int core_id)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(core_id, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0)
    {
        std::cerr << "Failed to pin thread to core " << core_id << ": " << strerror(errno) << "\n";
    }
}

// power-sampling thread
void power_thread_fn()
{
    pin_to_core(1);
    while (sampling.load())
    {
        float power_mW, current_mA;
        ina.readMeasurements(power_mW, current_mA);
        {
            std::lock_guard<std::mutex> lk(samples_mtx);
            power_samples.push_back(power_mW);
            current_samples.push_back(current_mA);
        }
        std::this_thread::sleep_for(std::chrono::microseconds(1200));
    }
}

// CPU usage sampling thread
void cpu_thread_fn()
{
    pin_to_core(2);
    std::ifstream proc_stat("/proc/stat");
    if (!proc_stat.is_open())
    {
        std::cerr << "Failed to open /proc/stat: " << strerror(errno) << "\n";
        return;
    }

    uint64_t prev_total = 0, prev_idle = 0;
    while (cpu_sampling.load())
    {
        proc_stat.clear();
        proc_stat.seekg(0);
        std::string line;
        while (std::getline(proc_stat, line))
        {
            if (line.find("cpu0") == 0) // Monitor core 0 (encryption/decryption)
            {
                std::istringstream iss(line);
                std::string cpu;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
                iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
                uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
                uint64_t idle_time = idle + iowait;

                if (prev_total != 0) // Skip first sample
                {
                    uint64_t delta_total = total - prev_total;
                    uint64_t delta_idle = idle_time - prev_idle;
                    float usage = delta_total ? 100.0f * (delta_total - delta_idle) / delta_total : 0.0f;
                    {
                        std::lock_guard<std::mutex> lk(samples_mtx);
                        cpu_usage_samples.push_back(usage);
                    }
                }
                prev_total = total;
                prev_idle = idle_time;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Sample every 10ms
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

    // Pin main thread to core 0
    pin_to_core(0);

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

    // Reserve space for sample vectors to reduce reallocations
    power_samples.reserve(1000);
    current_samples.reserve(1000);
    cpu_usage_samples.reserve(1000);

    // start power and CPU threads
    sampling.store(true);
    cpu_sampling.store(true);
    std::thread pwr_thread(power_thread_fn);
    std::thread cpu_thread(cpu_thread_fn);

    // capture baseline
    auto t0 = std::chrono::high_resolution_clock::now();

    // encryption
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher c{};
        int r = Speck_Init(&c, cfg_128_64, CBC, key, iv, nullptr);
        if (r)
        {
            sampling.store(false);
            cpu_sampling.store(false);
            pwr_thread.join();
            cpu_thread.join();
            return 1;
        }
        for (size_t b = 0; b < pad_len / BLOCK_SIZE; ++b)
            Speck_Encrypt(c, pt.data() + b * BLOCK_SIZE, ct.data() + b * BLOCK_SIZE);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    // decryption
    for (size_t it = 0; it < iterations; ++it)
    {
        SimSpk_Cipher c{};
        int r = Speck_Init(&c, cfg_128_64, CBC, key, iv, nullptr);
        if (r)
        {
            sampling.store(false);
            cpu_sampling.store(false);
            pwr_thread.join();
            cpu_thread.join();
            return 1;
        }
        for (size_t b = 0; b < pad_len / BLOCK_SIZE; ++b)
            Speck_Decrypt(c, ct.data() + b * BLOCK_SIZE, dt.data() + b * BLOCK_SIZE);
    }
    auto t3 = std::chrono::high_resolution_clock::now();

    // stop sampling
    sampling.store(false);
    cpu_sampling.store(false);
    pwr_thread.join();
    cpu_thread.join();

    // Get RAM usage
    struct rusage ru_end;
    getrusage(RUSAGE_SELF, &ru_end);

    // Get program size (ROM/flash estimate)
    struct stat st;
    off_t program_size = 0;
    if (stat("./speck_bench_cbc_arm64", &st) == 0)
    {
        program_size = st.st_size;
    }
    else
    {
        std::cerr << "Failed to get program size: " << strerror(errno) << "\n";
        std::cerr << "Run 'aarch64-linux-gnu-size speck_bench_cbc_arm64' after compilation to get accurate ROM usage.\n";
    }

    // compute power, current, and CPU stats
    double power_sum = 0, current_sum = 0, cpu_sum = 0;
    size_t sample_count = 0;
    {
        std::lock_guard<std::mutex> lk(samples_mtx);
        sample_count = power_samples.size();
        for (size_t i = 0; i < sample_count; ++i)
        {
            power_sum += power_samples[i];
            current_sum += current_samples[i];
        }
        for (float usage : cpu_usage_samples)
        {
            cpu_sum += usage;
        }
    }
    double avg_p = sample_count ? power_sum / sample_count : 0;
    double avg_curr_mA = sample_count ? current_sum / sample_count : 0;
    double avg_cpu = cpu_usage_samples.empty() ? 0 : cpu_sum / cpu_usage_samples.size();
    double dur_s = std::chrono::duration<double>(t3 - t0).count();
    double e_mJ = avg_p * dur_s;

    // timing
    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double dec_us = std::chrono::duration<double, std::micro>(t3 - t1).count();
    double latency_e = enc_us / iterations;
    double latency_d = dec_us / iterations;
    double tp_e = (pad_len * 1e6) / latency_e; // Throughput = DataSize * 10^6 / AvgExecTime
    double tp_d = (pad_len * 1e6) / latency_d;

    long ram = ru_end.ru_maxrss * 1024;

    std::cout
        << "\nEnc=" << enc_us << " us\n"
        << "Dec=" << dec_us << " us\n"
        << "LatencyEnc=" << latency_e << " us\n"
        << "LatencyDec=" << latency_d << " us\n"
        << "ThroughputEnc=" << tp_e << " B/s\n"
        << "ThroughputDec=" << tp_d << " B/s\n"
        << "PeakRAM=" << ram << " bytes\n"
        << "ProgramSize=" << program_size << " bytes (run 'aarch64-linux-gnu-size speck_bench_cbc_arm64' for accurate ROM usage)\n\n"
        << "PowerSamples=" << sample_count << "\n"
        << "AvgPower=" << avg_p << " mW\n"
        << "AvgCurrent=" << avg_curr_mA << " mA\n"
        << "AvgCPUUsage=" << avg_cpu << " %\n"
        << "Energy=" << e_mJ << " mJ\n";

    return 0;
}