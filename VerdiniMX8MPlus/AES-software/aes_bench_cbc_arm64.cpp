#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Enable GNU extensions for CPU_SET
#endif
#define NDEBUG // Disable debug output (if applicable)

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
#include <stack>
#include <cmath>
#include <stdexcept>

#include "aes.h"

void verify_decryption(const std::vector<uint8_t> &pt, const std::vector<uint8_t> &dt, size_t data_len)
{
    std::string original(pt.begin(), pt.begin() + data_len);
    std::string decrypted(dt.begin(), dt.begin() + data_len);

    std::cout << "\n--- Verification ---\n";
    std::cout << "Original : " << original << "\n";
    std::cout << "Decrypted: " << decrypted << "\n";

    if (original == decrypted)
    {
        std::cout << "✅ Match: Decryption successful\n";
    }
    else
    {
        std::cout << "❌ Mismatch: Decryption failed\n";
    }
}

double eval_expr(const std::string &expr)
{
    std::stack<double> values;
    std::stack<char> ops;

    auto precedence = [](char op)
    {
        if (op == '+' || op == '-')
            return 1;
        if (op == '*' || op == '/')
            return 2;
        return 0;
    };

    auto apply_op = [](double a, double b, char op) -> double
    {
        switch (op)
        {
        case '+':
            return a + b;
        case '-':
            return a - b;
        case '*':
            return a * b;
        case '/':
            if (b == 0.0)
                throw std::runtime_error("Divide by zero");
            return a / b;
        default:
            throw std::runtime_error("Unknown operator");
        }
    };

    size_t i = 0;
    while (i < expr.size())
    {
        char ch = expr[i];

        if (std::isspace(ch))
        {
            ++i;
            continue;
        }

        if (std::isdigit(ch) || ch == '.')
        {
            std::string num;
            while (i < expr.size() && (std::isdigit(expr[i]) || expr[i] == '.'))
            {
                num += expr[i++];
            }
            values.push(std::stod(num));
            continue;
        }

        if (ch == '(')
        {
            ops.push(ch);
        }
        else if (ch == ')')
        {
            while (!ops.empty() && ops.top() != '(')
            {
                double b = values.top();
                values.pop();
                double a = values.top();
                values.pop();
                char op = ops.top();
                ops.pop();
                values.push(apply_op(a, b, op));
            }
            if (ops.empty() || ops.top() != '(')
                throw std::runtime_error("Mismatched parentheses");
            ops.pop(); // Remove '('
        }
        else if (ch == '+' || ch == '-' || ch == '*' || ch == '/')
        {
            while (!ops.empty() && precedence(ops.top()) >= precedence(ch))
            {
                double b = values.top();
                values.pop();
                double a = values.top();
                values.pop();
                char op = ops.top();
                ops.pop();
                values.push(apply_op(a, b, op));
            }
            ops.push(ch);
        }
        else
        {
            throw std::runtime_error(std::string("Invalid character: ") + ch);
        }

        ++i;
    }

    while (!ops.empty())
    {
        double b = values.top();
        values.pop();
        double a = values.top();
        values.pop();
        char op = ops.top();
        ops.pop();
        values.push(apply_op(a, b, op));
    }

    if (values.size() != 1)
        throw std::runtime_error("Malformed expression");

    return values.top();
}

// INA219 settings (via hwmon)
// INA219 sensor is on hwmon2 for Verdin iMX8M Plus (verified via /sys/class/hwmon/hwmon2/name)
static const char *HWMON_PATH = "/sys/class/hwmon/hwmon2";

class INA219
{
    std::string power_path, current_path, voltage_path;
    bool initialized;

public:
    INA219(const char *hwmon_path) : initialized(false)
    {
        power_path = std::string(hwmon_path) + "/power1_input";
        current_path = std::string(hwmon_path) + "/curr1_input";
        voltage_path = std::string(hwmon_path) + "/in1_input";
        // Verify files exist
        std::ifstream f_power(power_path);
        if (!f_power.is_open())
        {
            std::cerr << "[DEBUG] Cannot open power file " << power_path << ": " << strerror(errno) << "\n";
            return;
        }
        std::ifstream f_current(current_path);
        if (!f_current.is_open())
        {
            std::cerr << "[DEBUG] Cannot open current file " << current_path << ": " << strerror(errno) << "\n";
            return;
        }
        std::ifstream f_voltage(voltage_path);
        if (!f_voltage.is_open())
        {
            std::cerr << "[DEBUG] Cannot open voltage file " << voltage_path << ": " << strerror(errno) << "\n";
            return;
        }
        initialized = true;
        std::cerr << "[DEBUG] INA219 initialized successfully\n";
    }

    bool begin()
    {
        if (!initialized)
        {
            std::cerr << "[DEBUG] INA219 begin failed: not initialized\n";
            return false;
        }
        // Verify files are still accessible
        std::ifstream f_power(power_path);
        std::ifstream f_current(current_path);
        std::ifstream f_voltage(voltage_path);
        bool accessible = f_power.is_open() && f_current.is_open() && f_voltage.is_open();
        if (!accessible)
        {
            std::cerr << "[DEBUG] INA219 begin failed: power file accessible=" << f_power.is_open()
                      << ", current file accessible=" << f_current.is_open()
                      << ", voltage file accessible=" << f_voltage.is_open() << "\n";
        }
        else
        {
            std::cerr << "[DEBUG] INA219 begin successful\n";
        }
        return accessible;
    }

    bool readMeasurements(float &power_W, float &current_A, float &voltage_V)
    {
        if (!initialized)
        {
            std::cerr << "[DEBUG] readMeasurements failed: INA219 not initialized\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read power
        std::ifstream f_power(power_path);
        if (!f_power.is_open())
        {
            std::cerr << "[DEBUG] Failed to read " << power_path << ": " << strerror(errno) << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        std::string line;
        std::getline(f_power, line);
        try
        {
            // power1_input is in microwatts; convert to watts
            power_W = std::stof(line) / 1000000.0f;
            // Validate power_W (0 to 10 W, typical for INA219)
            if (power_W < 0 || power_W > 10)
            {
                std::cerr << "[DEBUG] Invalid power reading: " << power_W << " W from " << power_path << ": " << line << "\n";
                power_W = 0;
                current_A = 0;
                voltage_V = 0;
                return false;
            }
        }
        catch (...)
        {
            std::cerr << "[DEBUG] Invalid power reading from " << power_path << ": " << line << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read current
        std::ifstream f_current(current_path);
        if (!f_current.is_open())
        {
            std::cerr << "[DEBUG] Failed to read " << current_path << ": " << strerror(errno) << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        std::getline(f_current, line);
        try
        {
            // curr1_input is in microamps; convert to amps
            float raw_current_A = std::stof(line) / 1000000.0f;
            // Validate current_A (0 to 1 A, typical for INA219)
            if (raw_current_A < 0 || raw_current_A > 1)
            {
                std::cerr << "[DEBUG] Invalid current reading: " << raw_current_A << " A from " << current_path << ": " << line << "\n";
                power_W = 0;
                current_A = 0;
                voltage_V = 0;
                return false;
            }
            current_A = raw_current_A;
        }
        catch (...)
        {
            std::cerr << "[DEBUG] Invalid current reading from " << current_path << ": " << line << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read voltage
        std::ifstream f_voltage(voltage_path);
        if (!f_voltage.is_open())
        {
            std::cerr << "[DEBUG] Failed to read " << voltage_path << ": " << strerror(errno) << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        std::getline(f_voltage, line);
        try
        {
            // in1_input is in millivolts; convert to volts
            voltage_V = std::stof(line) / 1000.0f;
            // Validate voltage_V (0 to 26 V, max for INA219)
            if (voltage_V < 0 || voltage_V > 26)
            {
                std::cerr << "[DEBUG] Invalid voltage reading: " << voltage_V << " V from " << voltage_path << ": " << line << "\n";
                power_W = 0;
                current_A = 0;
                voltage_V = 0;
                return false;
            }
        }
        catch (...)
        {
            std::cerr << "[DEBUG] Invalid voltage reading from " << voltage_path << ": " << line << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        return true;
    }
};

INA219 ina(HWMON_PATH);

// Power, current, voltage, and CPU sampling control
std::atomic<bool> sampling{false};
std::atomic<bool> cpu_sampling{false};
std::vector<float> power_samples, current_samples, voltage_samples;
std::vector<float> cpu_usage_samples;
std::mutex samples_mtx;

// Pin thread to specific core
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

// Power-sampling thread
void power_thread_fn()
{
    pin_to_core(1);
    while (sampling.load())
    {
        float power_W, current_A, voltage_V;
        if (ina.readMeasurements(power_W, current_A, voltage_V))
        {
            std::lock_guard<std::mutex> lk(samples_mtx);
            power_samples.push_back(power_W);
            current_samples.push_back(current_A);
            voltage_samples.push_back(voltage_V);
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::microseconds(1200));
            continue;
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
        std::cerr << "[DEBUG] Failed to open /proc/stat: " << strerror(errno) << "\n";
        return;
    }

    uint64_t prev_total = 0, prev_idle = 0;
    while (cpu_sampling.load())
    {
        proc_stat.clear();
        proc_stat.seekg(0);
        std::string line;
        bool found_cpu0 = false;
        while (std::getline(proc_stat, line))
        {
            if (line.find("cpu0") == 0) // Monitor core 0 (encryption/decryption)
            {
                found_cpu0 = true;
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
        if (!found_cpu0)
        {
            std::cerr << "[DEBUG] cpu0 not found in /proc/stat\n";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Sample every 10ms
    }
}

// Function to join a thread with a timeout
bool join_thread_with_timeout(std::thread &t, int timeout_ms)
{
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
               .count() < timeout_ms)
    {
        if (t.joinable())
        {
            t.join();
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cerr << "Warning: Thread join timed out after " << timeout_ms << " ms\n";
    return false;
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

    // Init INA219
    bool power_sampling_enabled = ina.begin();
    if (!power_sampling_enabled)
    {
        std::cerr << "Warning: Power and current sampling disabled due to INA219 failure\n";
    }

    // Prepare data
    const size_t BLOCK_SIZE = AES_BLOCKLEN, KEY_SIZE = AES_KEYLEN;
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
    voltage_samples.reserve(1000);
    cpu_usage_samples.reserve(1000);

    // Start power and CPU threads
    std::thread pwr_thread;
    if (power_sampling_enabled)
    {
        sampling.store(true);
        pwr_thread = std::thread(power_thread_fn);
    }
    cpu_sampling.store(true);
    std::thread cpu_thread(cpu_thread_fn);

    // Capture baseline
    auto t0 = std::chrono::high_resolution_clock::now();

    // Encryption
    for (size_t it = 0; it < iterations; ++it)
    {
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key, iv);
        memcpy(ct.data(), pt.data(), pad_len); // Copy plaintext to ct
        AES_CBC_encrypt_buffer(&ctx, ct.data(), pad_len);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    // Decryption
    for (size_t it = 0; it < iterations; ++it)
    {
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key, iv);
        memcpy(dt.data(), ct.data(), pad_len); // Copy ciphertext to dt
        AES_CBC_decrypt_buffer(&ctx, dt.data(), pad_len);
    }
    auto t3 = std::chrono::high_resolution_clock::now();

    // Stop sampling
    sampling.store(false);
    cpu_sampling.store(false);

    // Join threads with timeout
    if (power_sampling_enabled)
    {
        if (!join_thread_with_timeout(pwr_thread, 5000))
        {
            std::cerr << "Power thread failed to join\n";
        }
    }
    if (!join_thread_with_timeout(cpu_thread, 5000))
    {
        std::cerr << "CPU thread failed to join\n";
    }

    // Get RAM usage
    struct rusage ru_end;
    getrusage(RUSAGE_SELF, &ru_end);

    // Get program size (ROM/flash estimate)
    struct stat st;
    off_t program_size = 0;
    if (stat("./aes_bench_cbc_arm64", &st) == 0)
    {
        program_size = st.st_size;
    }
    else
    {
        std::cerr << "Failed to get program size: " << strerror(errno) << "\n";
        std::cerr << "Run 'aarch64-linux-gnu-size aes_bench_cbc_arm64' for accurate ROM usage.\n";
    }

    // Compute power, current, voltage, and CPU stats
    double power_sum = 0, current_sum = 0, voltage_sum = 0, cpu_sum = 0;
    size_t sample_count = 0;
    {
        std::lock_guard<std::mutex> lk(samples_mtx);
        sample_count = power_samples.size();
        for (size_t i = 0; i < sample_count; ++i)
        {
            power_sum += power_samples[i];
            current_sum += current_samples[i];
            voltage_sum += voltage_samples[i];
        }
        for (float usage : cpu_usage_samples)
        {
            cpu_sum += usage;
        }
    }
    double avg_p = sample_count ? power_sum / sample_count : 0;
    double avg_curr_A = sample_count ? current_sum / sample_count : 0;
    double avg_volt_V = sample_count ? voltage_sum / sample_count : 0;
    double avg_cpu = cpu_usage_samples.empty() ? 0 : cpu_sum / cpu_usage_samples.size();
    double dur_s = std::chrono::duration<double>(t3 - t0).count();
    double e_J = avg_p * dur_s;

    // Timing
    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double dec_us = std::chrono::duration<double, std::micro>(t3 - t1).count();
    double latency_e = enc_us / iterations;
    double latency_d = dec_us / iterations;
    double tp_e = (pad_len * 1e6) / latency_e; // Throughput = DataSize * 10^6 / AvgExecTime
    double tp_d = (pad_len * 1e6) / latency_d;

    long ram = ru_end.ru_maxrss * 1024;

    verify_decryption(pt, dt, data_len);

    // Sanitize decrypted string
    std::string decrypted;
    for (size_t i = 0; i < data_len; ++i)
        if (dt[i] >= 32 && dt[i] <= 126)
            decrypted += static_cast<char>(dt[i]);

    std::cout << "[DEBUG] Decrypted length: " << decrypted.size() << "\n";
    std::cout << "[DEBUG] Decrypted content: " << decrypted << "\n";

    // If expression ends with "=?", evaluate
    if (decrypted.size() > 2 && decrypted.substr(decrypted.size() - 2) == "=?")
    {
        std::string expr = decrypted.substr(0, decrypted.size() - 2);

        if (expr.empty())
            throw std::runtime_error("Empty expression");

        int balance = 0;
        for (char c : expr)
        {
            if (c == '(')
                balance++;
            else if (c == ')')
                balance--;
            if (balance < 0)
                throw std::runtime_error("Unmatched closing parenthesis");
        }
        if (balance != 0)
            throw std::runtime_error("Unbalanced parentheses");

        try
        {
            double result = eval_expr(expr);
            std::cout << "🧮 Expression Result: " << result << "\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "Expression evaluation error: " << e.what() << "\n";
        }
    }

    std::cout << "---------------------\n"
              << "Iterations=" << iterations << "\n"
              << "Enc=" << enc_us << " us\n"
              << "Dec=" << dec_us << " us\n"
              << "LatencyEnc=" << latency_e << " us\n"
              << "LatencyDec=" << latency_d << " us\n"
              << "ThroughputEnc=" << tp_e << " B/s\n"
              << "ThroughputDec=" << tp_d << " B/s\n"
              << "PeakRAM=" << ram << " bytes\n"
              << "ProgramSize=" << program_size << " bytes (run 'aarch64-linux-gnu-size aes_bench_cbc_arm64' for accurate ROM usage)\n\n"
              << "PowerSamples=" << sample_count << "\n"
              << "AvgCurrent=" << (avg_curr_A * 1000) << " A\n"
              << "AvgVoltage=" << avg_volt_V << " V\n"
              << "AvgCPUUsage=" << avg_cpu << " %\n"
              << "Energy=" << e_J << " J\n"
              << "---------------------\n";

    return 0;
}