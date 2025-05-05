#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Enable GNU extensions for CPU_SET
#endif
#define NDEBUG                  // Disable debug output (if applicable)
#define CHACHA20_IMPLEMENTATION // Include ChaCha20 implementation

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
#include <filesystem>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h> // For I2C communication
#include <linux/i2c.h>     // For I2C structs

#include "chacha.h"

// INA226 I2C address and register definitions
#define INA226_ADDRESS 0x40
#define INA226_REG_CONFIG 0x00
#define INA226_REG_SHUNT_VOLTAGE 0x01
#define INA226_REG_BUS_VOLTAGE 0x02
#define INA226_REG_POWER 0x03
#define INA226_REG_CURRENT 0x04
#define INA226_REG_CALIBRATION 0x05
#define INA226_SHUNT_RESISTOR 0.1f                    // 0.1 Ohm shunt resistor
#define INA226_CURRENT_LSB 0.0001f                    // 100 uA per LSB (adjust based on calibration)
#define INA226_POWER_LSB (25.0f * INA226_CURRENT_LSB) // Power LSB = 25 * Current LSB

void verify_decryption(const std::vector<uint8_t> &pt, const std::vector<uint8_t> &dt, size_t data_len, bool is_image, const std::string &output_image_path = "")
{
    if (is_image)
    {
        bool match = (pt.size() >= data_len && dt.size() >= data_len &&
                      std::equal(pt.begin(), pt.begin() + data_len, dt.begin()));
        std::cout << "\n--- Verification ---\n";
        std::cout << "Image verification: " << (match ? "✅ Match: Decryption successful" : "❌ Mismatch: Decryption failed") << "\n";

        if (!output_image_path.empty())
        {
            std::ofstream out_file(output_image_path, std::ios::binary);
            if (out_file.is_open())
            {
                out_file.write(reinterpret_cast<const char *>(dt.data()), data_len);
                out_file.close();
                std::cout << "Decrypted image saved to: " << output_image_path << "\n";
            }
            else
            {
                std::cerr << "Failed to save decrypted image to " << output_image_path << ": " << strerror(errno) << "\n";
            }
        }
    }
    else
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
            ops.pop();
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

class INA226
{
    int i2c_fd;
    bool initialized;

    // Write to INA226 register
    bool write_register(uint8_t reg, uint16_t value)
    {
        struct i2c_msg messages[1];
        struct i2c_rdwr_ioctl_data packets;
        uint8_t buf[3];

        buf[0] = reg;
        buf[1] = (value >> 8) & 0xFF; // MSB
        buf[2] = value & 0xFF;        // LSB

        messages[0].addr = INA226_ADDRESS;
        messages[0].flags = 0; // Write
        messages[0].len = 3;
        messages[0].buf = buf;

        packets.msgs = messages;
        packets.nmsgs = 1;

        if (ioctl(i2c_fd, I2C_RDWR, &packets) < 0)
        {
            std::cerr << "[DEBUG] Failed to write to INA226 register 0x" << std::hex << (int)reg << ": " << strerror(errno) << "\n";
            return false;
        }
        return true;
    }

    // Read from INA226 register
    bool read_register(uint8_t reg, uint16_t &value)
    {
        struct i2c_msg messages[2];
        struct i2c_rdwr_ioctl_data packets;
        uint8_t reg_buf[1] = {reg};
        uint8_t data[2];

        // Write register address
        messages[0].addr = INA226_ADDRESS;
        messages[0].flags = 0; // Write
        messages[0].len = 1;
        messages[0].buf = reg_buf;

        // Read data
        messages[1].addr = INA226_ADDRESS;
        messages[1].flags = I2C_M_RD; // Read
        messages[1].len = 2;
        messages[1].buf = data;

        packets.msgs = messages;
        packets.nmsgs = 2;

        if (ioctl(i2c_fd, I2C_RDWR, &packets) < 0)
        {
            std::cerr << "[DEBUG] Failed to read from INA226 register 0x" << std::hex << (int)reg << ": " << strerror(errno) << "\n";
            return false;
        }

        value = (data[0] << 8) | data[1];
        return true;
    }

public:
    INA226(const char *i2c_device = "/dev/i2c-3") : i2c_fd(-1), initialized(false)
    {
        // Open I2C device
        i2c_fd = open(i2c_device, O_RDWR);
        if (i2c_fd < 0)
        {
            std::cerr << "[DEBUG] Cannot open I2C device " << i2c_device << ": " << strerror(errno) << "\n";
            return;
        }

        // Configure INA226: Continuous mode, 1 sample averaging, 1.1ms conversion time
        uint16_t config = (0x4 << 13) | // Operating mode: Continuous shunt and bus
                          (0x4 << 9) |  // Shunt voltage conversion time: 1.1ms
                          (0x4 << 6) |  // Bus voltage conversion time: 1.1ms
                          (0x0 << 3) |  // Averaging: 1 sample
                          (0x7);        // Reserved
        if (!write_register(INA226_REG_CONFIG, config))
        {
            std::cerr << "[DEBUG] Failed to configure INA226\n";
            close(i2c_fd);
            i2c_fd = -1;
            return;
        }

        // Set calibration register
        // Current_LSB = 100uA, Max current = 0.8A, Shunt = 0.1 Ohm
        // Calibration = 0.00512 / (Current_LSB * Shunt) = 0.00512 / (0.0001 * 0.1) = 512
        uint16_t calibration = 512;
        if (!write_register(INA226_REG_CALIBRATION, calibration))
        {
            std::cerr << "[DEBUG] Failed to set INA226 calibration\n";
            close(i2c_fd);
            i2c_fd = -1;
            return;
        }

        initialized = true;
        std::cerr << "[DEBUG] INA226 initialized successfully\n";
    }

    ~INA226()
    {
        if (i2c_fd >= 0)
        {
            close(i2c_fd);
        }
    }

    bool begin()
    {
        if (!initialized)
        {
            std::cerr << "[DEBUG] INA226 begin failed: not initialized\n";
            return false;
        }
        // Verify communication by reading configuration
        uint16_t config;
        if (!read_register(INA226_REG_CONFIG, config))
        {
            std::cerr << "[DEBUG] INA226 begin failed: cannot read configuration\n";
            return false;
        }
        std::cerr << "[DEBUG] INA226 begin successful\n";
        return true;
    }

    bool readMeasurements(float &power_W, float &current_A, float &voltage_V)
    {
        if (!initialized)
        {
            std::cerr << "[DEBUG] readMeasurements failed: INA226 not initialized\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read bus voltage (1.25mV per LSB)
        uint16_t bus_voltage_raw;
        if (!read_register(INA226_REG_BUS_VOLTAGE, bus_voltage_raw))
        {
            std::cerr << "[DEBUG] Failed to read bus voltage\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        voltage_V = bus_voltage_raw * 0.00125f; // Convert to volts
        if (voltage_V < 0 || voltage_V > 36)
        {
            std::cerr << "[DEBUG] Invalid voltage reading: " << voltage_V << " V\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read current (100uA per LSB)
        uint16_t current_raw;
        if (!read_register(INA226_REG_CURRENT, current_raw))
        {
            std::cerr << "[DEBUG] Failed to read current\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        current_A = (int16_t)current_raw * INA226_CURRENT_LSB; // Convert to amps
        if (current_A < -0.8f || current_A > 0.8f)
        {
            std::cerr << "[DEBUG] Invalid current reading: " << current_A << " A\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        // Read power (Power_LSB = 25 * Current_LSB)
        uint16_t power_raw;
        if (!read_register(INA226_REG_POWER, power_raw))
        {
            std::cerr << "[DEBUG] Failed to read power\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
        power_W = power_raw * INA226_POWER_LSB; // Convert to watts
        if (power_W < 0 || power_W > 10)
        {
            std::cerr << "[DEBUG] Invalid power reading: " << power_W << " W\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }

        return true;
    }
};

INA226 ina("/dev/i2c-3");

std::atomic<bool> sampling{false};
std::atomic<bool> cpu_sampling{false};
std::vector<float> power_samples, current_samples, voltage_samples;
std::vector<float> cpu_usage_samples;
std::mutex samples_mtx;

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
            if (line.find("cpu0") == 0)
            {
                found_cpu0 = true;
                std::istringstream iss(line);
                std::string cpu;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
                iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
                uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
                uint64_t idle_time = idle + iowait;

                if (prev_total != 0)
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
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

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
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cerr << "Warning: Thread join timed out after " << timeout_ms << " ms\n";
    return false;
}

std::vector<uint8_t> read_file(const std::string &filename, size_t &data_len)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file " + filename + ": " + strerror(errno));
    }
    data_len = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(data_len);
    file.read(reinterpret_cast<char *>(buffer.data()), data_len);
    file.close();
    std::cout << "[DEBUG] Successfully read file " << filename << " (" << data_len << " bytes)\n";
    return buffer;
}

bool file_exists(const std::string &filename)
{
    std::ifstream file(filename);
    return file.good();
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <iterations> <input>\n";
        std::cerr << "  - <iterations>: Number of encryption/decryption iterations\n";
        std::cerr << "  - <input>: Plaintext string or path to an image file\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << argv[0] << " 5000 \"(10 + 5) * 2 =?\"\n";
        std::cerr << "  " << argv[0] << " 5000 image.jpg\n";
        return 1;
    }

    size_t iterations;
    try
    {
        iterations = std::stoul(argv[1]);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Invalid iterations: " << argv[1] << "\n";
        return 1;
    }
    std::string input_arg = argv[2];
    bool is_image = file_exists(input_arg);
    std::string image_path = is_image ? input_arg : "";
    std::string output_image_path;

    pin_to_core(0);

    bool power_sampling_enabled = ina.begin();
    if (!power_sampling_enabled)
    {
        std::cerr << "Warning: Power and current sampling disabled due to INA226 failure\n";
    }

    const size_t BLOCK_SIZE = 64; // ChaCha20 block size
    size_t data_len;
    std::vector<uint8_t> pt, ct, dt;
    key256_t key;
    nonce96_t nonce = {0};
    for (size_t i = 0; i < 32; i++)
        key[i] = uint8_t(i); // Simple key for testing

    if (is_image)
    {
        std::cout << "[DEBUG] Processing image file: " << input_arg << "\n";
        try
        {
            pt = read_file(image_path, data_len);
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << e.what() << "\n";
            return 1;
        }
        std::filesystem::path p(image_path);
        output_image_path = "decrypted_image" + p.extension().string();
    }
    else
    {
        std::cout << "[DEBUG] Processing plaintext: " << input_arg << "\n";
        data_len = input_arg.size();
        pt.resize(data_len);
        memcpy(pt.data(), input_arg.data(), data_len);
    }

    size_t pad_len = ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    pt.resize(pad_len, 0);
    ct.resize(pad_len);
    dt.resize(pad_len);

    power_samples.reserve(1000);
    current_samples.reserve(1000);
    voltage_samples.reserve(1000);
    cpu_usage_samples.reserve(1000);

    std::thread pwr_thread;
    if (power_sampling_enabled)
    {
        sampling.store(true);
        pwr_thread = std::thread(power_thread_fn);
    }
    cpu_sampling.store(true);
    std::thread cpu_thread(cpu_thread_fn);

    auto t0 = std::chrono::high_resolution_clock::now();

    for (size_t it = 0; it < iterations; ++it)
    {
        ChaCha20_Ctx ctx;
        ChaCha20_init(&ctx, key, nonce, 0);
        memcpy(ct.data(), pt.data(), pad_len);
        ChaCha20_xor(&ctx, ct.data(), pad_len);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    for (size_t it = 0; it < iterations; ++it)
    {
        ChaCha20_Ctx ctx;
        ChaCha20_init(&ctx, key, nonce, 0);
        memcpy(dt.data(), ct.data(), pad_len);
        ChaCha20_xor(&ctx, dt.data(), pad_len);
    }
    auto t3 = std::chrono::high_resolution_clock::now();

    sampling.store(false);
    cpu_sampling.store(false);

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

    struct rusage ru_end;
    getrusage(RUSAGE_SELF, &ru_end);

    struct stat st;
    off_t program_size = 0;
    if (stat("./chacha_bench_cbc_arm64", &st) == 0)
    {
        program_size = st.st_size;
    }
    else
    {
        std::cerr << "Failed to get program size: " << strerror(errno) << "\n";
        std::cerr << "Run 'aarch64-linux-gnu-size chacha_bench_cbc_arm64' for accurate ROM usage.\n";
    }

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

    double enc_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double dec_us = std::chrono::duration<double, std::micro>(t3 - t1).count();
    double latency_e = enc_us / iterations;
    double latency_d = dec_us / iterations;
    double tp_e = (pad_len * 1e6) / latency_e;
    double tp_d = (pad_len * 1e6) / latency_d;

    long ram = ru_end.ru_maxrss * 1024;

    verify_decryption(pt, dt, data_len, is_image, output_image_path);

    if (!is_image)
    {
        std::string decrypted;
        for (size_t i = 0; i < data_len; ++i)
            if (dt[i] >= 32 && dt[i] <= 126)
                decrypted += static_cast<char>(dt[i]);

        std::cout << "[DEBUG] Decrypted length: " << decrypted.size() << "\n";
        std::cout << "[DEBUG] Decrypted content: " << decrypted << "\n";

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
              << "ProgramSize=" << program_size << " bytes (run 'aarch64-linux-gnu-size chacha_bench_cbc_arm64' for accurate ROM usage)\n\n"
              << "AvgPower=" << avg_p << " W\n"
              << "PowerSamples=" << sample_count << "\n"
              << "AvgCurrent=" << (avg_curr_A * 1000) << " mA\n"
              << "AvgVoltage=" << avg_volt_V << " V\n"
              << "AvgCPUUsage=" << avg_cpu << " %\n"
              << "Energy=" << e_J << " J\n"
              << "---------------------\n";

    return 0;
}