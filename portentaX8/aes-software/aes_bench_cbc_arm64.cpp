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
#include <filesystem>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h> // For I2C communication
#include <linux/i2c.h>     // For I2C structs

#include "aes.h"

// INA226 I2C address and register definitions
#define INA226_ADDRESS 0x40  // Adresse bekreftet via i2cget
#define INA226_REG_CONFIG 0x00
#define INA226_REG_SHUNT_VOLTAGE 0x01
#define INA226_REG_BUS_VOLTAGE 0x02
#define INA226_REG_POWER 0x03
#define INA226_REG_CURRENT 0x04
#define INA226_REG_CALIBRATION 0x05
#define INA226_SHUNT_RESISTOR 0.1f  // 0.1 Ohm shunt resistor
#define INA226_CURRENT_LSB 0.0001f  // 100 uA per LSB (juster basert på kalibrering)
#define INA226_POWER_LSB (25.0f * INA226_CURRENT_LSB) // Power LSB = 25 * Current LSB

// Direktekommunikasjon med INA226 på I2C-buss 3
class INA226
{
private:
    int i2c_fd;
    bool initialized;
    const int bus_id = 3;  // Hardkodet buss 3 hvor sensoren er funnet

    // Write to INA226 register
    bool write_register(uint8_t reg, uint16_t value)
    {
        uint8_t buf[3];
        buf[0] = reg;
        buf[1] = (value >> 8) & 0xFF; // MSB
        buf[2] = value & 0xFF;        // LSB

        if (write(i2c_fd, buf, 3) != 3)
        {
            std::cerr << "[DEBUG] Failed to write to INA226 register 0x" << std::hex << (int)reg 
                      << " on bus " << bus_id << ": " << strerror(errno) << "\n";
            return false;
        }
        return true;
    }

    // Read from INA226 register
    bool read_register(uint8_t reg, uint16_t &value)
    {
        // Write register address
        if (write(i2c_fd, &reg, 1) != 1)
        {
            std::cerr << "[DEBUG] Failed to write register address 0x" << std::hex << (int)reg 
                      << " on bus " << bus_id << ": " << strerror(errno) << "\n";
            return false;
        }
        
        // Read data (2 bytes)
        uint8_t data[2];
        if (read(i2c_fd, data, 2) != 2)
        {
            std::cerr << "[DEBUG] Failed to read from INA226 register 0x" << std::hex << (int)reg 
                      << " on bus " << bus_id << ": " << strerror(errno) << "\n";
            return false;
        }

        value = (data[0] << 8) | data[1];
        return true;
    }

public:
    INA226() : i2c_fd(-1), initialized(false)
    {
        char device_path[64];
        sprintf(device_path, "/dev/i2c-%d", bus_id);
        
        // Open I2C device
        i2c_fd = open(device_path, O_RDWR);
        if (i2c_fd < 0)
        {
            std::cerr << "[DEBUG] Cannot open I2C device " << device_path << ": " << strerror(errno) << "\n";
            return;
        }
        
        // Set I2C slave address
        if (ioctl(i2c_fd, I2C_SLAVE, INA226_ADDRESS) < 0)
        {
            std::cerr << "[DEBUG] Failed to set INA226 I2C slave address: " << strerror(errno) << "\n";
            close(i2c_fd);
            i2c_fd = -1;
            return;
        }

        std::cout << "Successfully opened INA226 on I2C bus " << bus_id << " at address 0x" 
                  << std::hex << INA226_ADDRESS << std::dec << "\n";

        // Configure INA226: Continuous mode, 16 sample averaging, 1.1ms conversion time
        uint16_t config = (0x4 << 12) | // Operating mode: Continuous shunt and bus
                          (0x3 << 9) |  // Shunt voltage conversion time: 1.1ms
                          (0x3 << 6) |  // Bus voltage conversion time: 1.1ms
                          (0x3 << 3) |  // Averaging: 16 samples
                          (0x7);        // Reserved
        if (!write_register(INA226_REG_CONFIG, config))
        {
            std::cerr << "[DEBUG] Failed to configure INA226\n";
            close(i2c_fd);
            i2c_fd = -1;
            return;
        }

        // Set calibration register for 0.1 ohm shunt
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
        std::cout << "[INFO] INA226 initialized successfully on bus " << bus_id << "\n";
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
        
        std::cout << "[INFO] INA226 begin successful. Config register: 0x" << std::hex << config << std::dec << "\n";
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
            return false;
        }
        voltage_V = bus_voltage_raw * 0.00125f; // Convert to volts
        
        // Read current register
        uint16_t current_raw;
        if (!read_register(INA226_REG_CURRENT, current_raw))
        {
            std::cerr << "[DEBUG] Failed to read current\n";
            return false;
        }
        current_A = (int16_t)current_raw * INA226_CURRENT_LSB; // Convert to amps
        
        // Read power register
        uint16_t power_raw;
        if (!read_register(INA226_REG_POWER, power_raw))
        {
            std::cerr << "[DEBUG] Failed to read power\n";
            return false;
        }
        power_W = power_raw * INA226_POWER_LSB; // Convert to watts

        // Debugging output for first few readings
        static int reading_count = 0;
        if (reading_count < 5)
        {
            std::cout << "[DEBUG] INA226 Reading #" << reading_count 
                      << " - Voltage: " << voltage_V << "V, Current: " << (current_A * 1000.0f) 
                      << "mA, Power: " << (power_W * 1000.0f) << "mW\n";
            reading_count++;
        }

        return true;
    }
};

// Create global INA226 instance
INA226 ina;

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
    std::cout << "[INFO] Power sampling thread started\n";
    int sample_count = 0;
    
    while (sampling.load())
    {
        float power_W = 0.0f, current_A = 0.0f, voltage_V = 0.0f;
        bool valid_reading = ina.readMeasurements(power_W, current_A, voltage_V);
        
        if (valid_reading)
        {
            std::lock_guard<std::mutex> lk(samples_mtx);
            power_samples.push_back(power_W);
            current_samples.push_back(current_A);
            voltage_samples.push_back(voltage_V);
            sample_count++;
            
            if (sample_count % 100 == 0)
            {
                std::cout << "[INFO] Collected " << sample_count << " power samples\n";
            }
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Ikke samle for raskt for å unngå å overbelaste I2C-bussen
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::cout << "[INFO] Power sampling thread stopped, collected " << sample_count << " samples\n";
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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cerr << "Warning: Thread join timed out after " << timeout_ms << " ms\n";
    return false;
}

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
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        std::cout << "Usage: " << argv[0] << " <iterations> <input>\n";
        std::cout << "  - <iterations>: Number of encryption/decryption iterations\n";
        std::cout << "  - <input>: Plaintext string or path to an image file\n";
        std::cout << "Examples:\n";
        std::cout << "  " << argv[0] << " 5000 \"SAT-TEST-1234: Secure Transmission OK\"\n";
        std::cout << "  " << argv[0] << " 5000 \"(10 + 5) * 2 =?\"\n";
        std::cout << "  " << argv[0] << " 500 image.jpg\n\n";
        std::cout << "Note: For I2C access, you may need to run with sudo\n";
        return 0;
    }

    if (argc < 3) {
        if (argc > 1 && std::string(argv[1]) == "REPEAT" && argc >= 4) {
            // Special handling for REPEAT command format
            try {
                int iterations = std::stoi(argv[2]);
                std::string input_text = argv[3];
                for (int i = 4; i < argc; i++) {
                    input_text += " ";
                    input_text += argv[i];
                }
                
                // Reassign arguments for standard processing
                char** new_argv = new char*[3];
                new_argv[0] = argv[0];
                new_argv[1] = argv[2]; // iterations
                new_argv[2] = strdup(input_text.c_str());
                argv = new_argv;
                
                std::cout << "Running with REPEAT command: iterations=" << iterations 
                          << ", text=\"" << input_text << "\"\n";
            } catch (const std::exception& e) {
                std::cerr << "Error parsing REPEAT command: " << e.what() << "\n";
                return 1;
            }
        } else if (argc > 1 && std::string(argv[1]) == "IMAGE" && argc >= 4) {
            // Special handling for IMAGE command format
            try {
                int iterations = std::stoi(argv[2]);
                std::string filename = argv[3];
                
                // Reassign arguments for standard processing
                char** new_argv = new char*[3];
                new_argv[0] = argv[0];
                new_argv[1] = argv[2]; // iterations
                new_argv[2] = strdup(filename.c_str());
                argv = new_argv;
                
                std::cout << "Running with IMAGE command: iterations=" << iterations 
                          << ", file=\"" << filename << "\"\n";
            } catch (const std::exception& e) {
                std::cerr << "Error parsing IMAGE command: " << e.what() << "\n";
                return 1;
            }
        } else {
            std::cerr << "Usage: " << argv[0] << " <iterations> <input>\n";
            std::cerr << "Try '" << argv[0] << " --help' for more information.\n";
            return 1;
        }
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

    std::cout << "\n==========================================\n"
              << "         BENCHMARK STARTED\n"
              << "==========================================\n";
    std::cout << "Starting AES-CBC benchmark with " << iterations << " repetitions...\n";
    std::cout << "Input: \"" << (is_image ? image_path : input_arg) << "\" (" 
              << (is_image ? "image file" : std::to_string(input_arg.size()) + " bytes") << ")\n";

    bool power_sampling_enabled = ina.begin();
    if (!power_sampling_enabled)
    {
        std::cerr << "\nWarning: Power and current sampling disabled due to INA226 failure\n";
        std::cerr << "Running on Portenta X8 requires I2C permissions: try 'sudo " << argv[0] << " ...'\n";
    }

    const size_t BLOCK_SIZE = AES_BLOCKLEN, KEY_SIZE = AES_KEYLEN;
    size_t data_len;
    std::vector<uint8_t> pt, ct, dt;
    uint8_t key[KEY_SIZE], iv[BLOCK_SIZE] = {0};
    for (size_t i = 0; i < KEY_SIZE; i++)
        key[i] = uint8_t(i);

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
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key, iv);
        std::copy(pt.begin(), pt.end(), ct.begin());
        AES_CBC_encrypt_buffer(&ctx, ct.data(), pad_len);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    for (size_t it = 0; it < iterations; ++it)
    {
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key, iv);
        std::copy(ct.begin(), ct.end(), dt.begin());
        AES_CBC_decrypt_buffer(&ctx, dt.data(), pad_len);
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
    if (stat("./aes_bench_cbc_arm64", &st) == 0)
    {
        program_size = st.st_size;
    }
    else
    {
        std::cerr << "Failed to get program size: " << strerror(errno) << "\n";
        std::cerr << "Run 'aarch64-linux-gnu-size aes_bench_cbc_arm64' for accurate ROM usage.\n";
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

    std::cout << "\n==========================================\n"
              << "         POWER MEASUREMENTS\n"
              << "==========================================\n";
    std::cout << "Average current: " << (avg_curr_A * 1e6) << " μA (" << avg_curr_A << " A)\n";
    std::cout << "Bus voltage: " << avg_volt_V << " V\n";
    std::cout << "Average power: " << (avg_p * 1000) << " mW (" << avg_p << " W)\n";
    std::cout << "Energy consumption: " << (e_J * 1000) << " mJ (" << e_J << " J)\n";
    std::cout << "Energy in watt-hours: " << (e_J / 3600) << " Wh\n";
    std::cout << "Energy per operation: " << (e_J / iterations * 1000) << " mJ/op\n";
    std::cout << "Energy per byte: " << (e_J / (iterations * data_len) * 1e6) << " μJ/byte\n";

    std::cout << "\n==========================================\n"
              << "         BENCHMARK RESULTS\n"
              << "==========================================\n";
    std::cout << "Input " << (is_image ? "image" : "text") << ": \"" 
              << (is_image ? image_path : input_arg) << "\" (" 
              << data_len << " bytes, padded to " << pad_len << " bytes)\n";
    std::cout << "Total encryption time: " << enc_us << " µs\n";
    std::cout << "Total decryption time: " << dec_us << " µs\n";
    std::cout << "Total combined time: " << (enc_us + dec_us) << " µs\n";
    std::cout << "Total benchmark time: " << (enc_us + dec_us) / 1000 << " ms\n";
    std::cout << "CPU usage: " << avg_cpu << "%\n\n";

    std::cout << "Average time per operation:\n";
    std::cout << "  Encryption: " << latency_e << " µs\n";
    std::cout << "  Decryption: " << latency_d << " µs\n";
    std::cout << "  Combined average: " << (latency_e + latency_d) / 2 << " µs\n\n";

    std::cout << "Performance metrics:\n";
    std::cout << "Encryption throughput: " << tp_e << " bytes/s\n";
    std::cout << "Decryption throughput: " << tp_d << " bytes/s\n";
    std::cout << "Encryption goodput: " << (tp_e * data_len / pad_len) << " bytes/s\n";
    std::cout << "Decryption goodput: " << (tp_d * data_len / pad_len) << " bytes/s\n";
    std::cout << "Protocol overhead: " << (100.0 * (pad_len - data_len) / pad_len) << "%\n\n";

    std::cout << "Resource usage:\n";
    std::cout << "Peak RAM: " << ram << " bytes\n";
    std::cout << "Program size: " << program_size << " bytes\n";

    return 0;
}