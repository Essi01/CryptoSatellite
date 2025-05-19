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
#include <sstream>
#include <sys/stat.h> // For stat
#include <stack>
#include <cmath>
#include <stdexcept>
#include <sys/socket.h>
#include <linux/if_alg.h> // For AF_ALG
#include <openssl/evp.h>  // For OpenSSL AES fallback
#include <openssl/err.h>

// INA219 settings (via hwmon)
static const char *DEFAULT_HWMON_PATH = "/sys/class/hwmon/hwmon3";
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
            power_W = std::stof(line) / 1000000.0f;
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
            float raw_current_uA = std::stof(line);
            if (raw_current_uA < 0 || raw_current_uA > 1000000)
            {
                std::cerr << "[DEBUG] Invalid current reading: " << raw_current_uA
                          << " μA from " << current_path << ": " << line << "\n";
                power_W = 0;
                current_A = 0;
                voltage_V = 0;
                return false;
            }
            current_A = raw_current_uA / 1000000.0f; // Convert μA to A
        }
        catch (...)
        {
            std::cerr << "[DEBUG] Invalid current reading from " << current_path << ": " << line << "\n";
            power_W = 0;
            current_A = 0;
            voltage_V = 0;
            return false;
        }
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
            voltage_V = std::stof(line) / 1000.0f;
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
// Global INA219 object
INA219 ina(DEFAULT_HWMON_PATH);
// Power, current, voltage, and CPU sampling control
std::atomic<bool> sampling{false};
std::atomic<bool> cpu_sampling{false};
std::vector<float> power_samples, current_samples, voltage_samples;
std::vector<float> cpu_usage_samples;
std::mutex samples_mtx;

// Crypto API context for AES-CBC
struct CryptoContext
{
    int sfd;                 // Socket file descriptor
    int tfmfd;               // Transformation file descriptor
    bool use_fallback;       // Flag to indicate OpenSSL fallback
    EVP_CIPHER_CTX *enc_ctx; // OpenSSL encryption context
    EVP_CIPHER_CTX *dec_ctx; // OpenSSL decryption context

    CryptoContext(const char *alg_name, const uint8_t *key, size_t key_len)
        : sfd(-1), tfmfd(-1), use_fallback(false), enc_ctx(nullptr), dec_ctx(nullptr)
    {
        // Try AF_ALG first
        sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (sfd < 0)
        {
            std::cerr << "[DEBUG] AF_ALG socket creation failed: " << strerror(errno)
                      << " (errno=" << errno << "). Falling back to OpenSSL.\n";
            use_fallback = true;
        }
        else
        {
            struct sockaddr_alg sa = {
                .salg_family = AF_ALG,
                .salg_type = "skcipher",
            };
            strncpy((char *)sa.salg_name, alg_name, sizeof(sa.salg_name) - 1);
            if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            {
                std::cerr << "[DEBUG] AF_ALG bind failed: " << strerror(errno)
                          << " (errno=" << errno << "). Falling back to OpenSSL.\n";
                close(sfd);
                sfd = -1;
                use_fallback = true;
            }
            else
            {
                tfmfd = accept(sfd, NULL, 0);
                if (tfmfd < 0)
                {
                    std::cerr << "[DEBUG] AF_ALG accept failed: " << strerror(errno)
                              << " (errno=" << errno << "). Falling back to OpenSSL.\n";
                    close(sfd);
                    sfd = -1;
                    use_fallback = true;
                }
                else if (setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, key_len) < 0)
                {
                    std::cerr << "[DEBUG] AF_ALG set key failed: " << strerror(errno)
                              << " (errno=" << errno << "). Falling back to OpenSSL.\n";
                    close(tfmfd);
                    close(sfd);
                    sfd = -1;
                    tfmfd = -1;
                    use_fallback = true;
                }
            }
        }
        // Initialize OpenSSL fallback if AF_ALG failed
        if (use_fallback)
        {
            OpenSSL_add_all_algorithms();
            enc_ctx = EVP_CIPHER_CTX_new();
            dec_ctx = EVP_CIPHER_CTX_new();
            if (!enc_ctx || !dec_ctx)
            {
                throw std::runtime_error("Failed to create OpenSSL cipher contexts");
            }
            if (!EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_cbc(), NULL, key, NULL) ||
                !EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_cbc(), NULL, key, NULL))
            {
                EVP_CIPHER_CTX_free(enc_ctx);
                EVP_CIPHER_CTX_free(dec_ctx);
                throw std::runtime_error("Failed to initialize OpenSSL AES-CBC");
            }
        }
    }
    ~CryptoContext()
    {
        if (tfmfd >= 0)
            close(tfmfd);
        if (sfd >= 0)
            close(sfd);
        if (enc_ctx)
            EVP_CIPHER_CTX_free(enc_ctx);
        if (dec_ctx)
            EVP_CIPHER_CTX_free(dec_ctx);
    }
};

// Perform AES-CBC operation using OpenSSL
bool perform_openssl_operation(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len,
                               const uint8_t *iv, bool encrypt)
{
    int out_len = 0, total_len = 0;
    if (encrypt)
    {
        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) ||
            !EVP_EncryptUpdate(ctx, out, &out_len, in, len))
        {
            std::cerr << "OpenSSL encryption failed: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return false;
        }
        total_len = out_len;
        if (!EVP_EncryptFinal_ex(ctx, out + out_len, &out_len))
        {
            std::cerr << "OpenSSL encryption final failed: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return false;
        }
        total_len += out_len;
    }
    else
    {
        if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) ||
            !EVP_DecryptUpdate(ctx, out, &out_len, in, len))
        {
            std::cerr << "OpenSSL decryption failed: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return false;
        }
        total_len = out_len;
        if (!EVP_DecryptFinal_ex(ctx, out + out_len, &out_len))
        {
            std::cerr << "OpenSSL decryption final failed: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return false;
        }
        total_len += out_len;
    }
    if (total_len != (int)len)
    {
        std::cerr << "OpenSSL operation produced incorrect output length: expected "
                  << len << ", got " << total_len << "\n";
        return false;
    }
    return true;
}

// Perform AES-CBC operation (encrypt or decrypt) using CAAM or OpenSSL
bool perform_crypto_operation(CryptoContext &ctx, const uint8_t *in, uint8_t *out, size_t len,
                              const uint8_t *iv, bool encrypt)
{
    if (ctx.use_fallback)
    {
        return perform_openssl_operation(encrypt ? ctx.enc_ctx : ctx.dec_ctx, in, out, len, iv, encrypt);
    }
    if (len > UINT32_MAX)
    {
        std::cerr << "Input length " << len << " exceeds maximum supported size (" << UINT32_MAX << ")\n";
        return false;
    }
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(sizeof(uint32_t))];
    struct
    {
        uint32_t type;
        uint32_t length;
        uint8_t iv[16];
    } __attribute__((packed)) op = {
        .type = static_cast<uint32_t>(encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT),
        .length = static_cast<uint32_t>(len),
    };
    memcpy(op.iv, iv, 16);
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    memcpy(CMSG_DATA(cmsg), &op.type, sizeof(uint32_t));
    msg.msg_iov = (struct iovec *)malloc(sizeof(struct iovec));
    msg.msg_iovlen = 1;
    msg.msg_iov->iov_base = (void *)in;
    msg.msg_iov->iov_len = len;
    if (sendmsg(ctx.tfmfd, &msg, 0) < 0)
    {
        std::cerr << "Failed to send crypto operation: " << strerror(errno) << "\n";
        free(msg.msg_iov);
        return false;
    }
    free(msg.msg_iov);
    ssize_t read_len = read(ctx.tfmfd, out, len);
    if (read_len != (ssize_t)len)
    {
        std::cerr << "Failed to read crypto result: expected " << len << ", got " << read_len << "\n";
        return false;
    }
    return true;
}

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
            try
            {
                values.push(std::stod(num));
            }
            catch (const std::exception &e)
            {
                throw std::runtime_error("Invalid number: " + num);
            }
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
        if (ops.top() == '(')
            throw std::runtime_error("Unmatched opening parenthesis");
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
    uint64_t prev_total[4] = {0}, prev_idle[4] = {0};
    while (cpu_sampling.load())
    {
        proc_stat.clear();
        proc_stat.seekg(0);
        std::string line;
        int cpu_idx = 0;
        while (std::getline(proc_stat, line) && cpu_idx < 4)
        {
            if (line.find("cpu") == 0 && (line[3] == ' ' || (line[3] >= '0' && line[3] <= '2')))
            {
                std::istringstream iss(line);
                std::string cpu;
                uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
                iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
                uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
                uint64_t idle_time = idle + iowait;
                if (prev_total[cpu_idx] != 0)
                {
                    uint64_t delta_total = total - prev_total[cpu_idx];
                    uint64_t delta_idle = idle_time - prev_idle[cpu_idx];
                    float usage = delta_total ? 100.0f * (delta_total - delta_idle) / delta_total : 0.0f;
                    {
                        std::lock_guard<std::mutex> lk(samples_mtx);
                        if (cpu_idx == 0)
                            cpu_usage_samples.push_back(usage);
                        std::string cpu_name = (cpu_idx == 0) ? "Total" : "cpu" + std::to_string(cpu_idx - 1);
                        std::cerr << "[DEBUG] " << cpu_name << " usage: " << usage << "%, samples: "
                                  << (cpu_idx == 0 ? cpu_usage_samples.size() : cpu_idx) << "\n";
                    }
                }
                prev_total[cpu_idx] = total;
                prev_idle[cpu_idx] = idle_time;
                cpu_idx++;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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

void processImageFile(const char *filename, int iterations = 1)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }
    std::string file_extension = ".jpg";
    const char *dot = strrchr(filename, '.');
    if (dot && strlen(dot) < 15)
    {
        file_extension = dot;
    }
    std::string decrypted_filename = "decrypted" + file_extension;
    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::cout << "\nStarting image encryption for " << filename << " (" << filesize << " bytes)"
              << " with " << iterations << " iterations..." << std::endl;
    std::vector<uint8_t> buffer(filesize, 0);
    size_t padded_size = ((filesize + 16 - 1) / 16) * 16;
    std::vector<uint8_t> padded_buffer(padded_size, 0);
    std::vector<uint8_t> encrypted(padded_size, 0);
    std::vector<uint8_t> decrypted(padded_size, 0);
    if (fread(buffer.data(), 1, filesize, fp) != filesize)
    {
        std::cerr << "Failed to read entire file" << std::endl;
        fclose(fp);
        return;
    }
    fclose(fp);
    memcpy(padded_buffer.data(), buffer.data(), filesize);
    bool power_sampling_enabled = ina.begin();
    std::thread pwr_thread;
    std::thread cpu_thread;
    power_samples.clear();
    current_samples.clear();
    voltage_samples.clear();
    cpu_usage_samples.clear();
    if (power_sampling_enabled)
    {
        sampling.store(true);
        pwr_thread = std::thread(power_thread_fn);
    }
    cpu_sampling.store(true);
    cpu_thread = std::thread(cpu_thread_fn);
    uint8_t key[32], iv[16] = {0};
    for (size_t i = 0; i < 32; i++)
        key[i] = uint8_t(i);
    auto t0 = std::chrono::high_resolution_clock::now();
    try
    {
        CryptoContext crypto_ctx("cbc(aes)", key, 32);
        if (crypto_ctx.use_fallback)
        {
            std::cout << "[INFO] Using OpenSSL software AES-CBC (CAAM not available)\n";
        }
        else
        {
            std::cout << "[INFO] Using CAAM hardware acceleration for AES-CBC\n";
        }
        for (int i = 0; i < iterations; i++)
        {
            if (!perform_crypto_operation(crypto_ctx, padded_buffer.data(), encrypted.data(),
                                          padded_size, iv, true))
            {
                std::cerr << "Encryption failed at iteration " << i << std::endl;
                break;
            }
            if (i > 0 && i % 100 == 0)
            {
                std::cout << "." << std::flush;
                if (i % 500 == 0)
                {
                    std::cout << " " << i << " iterations completed\n";
                }
            }
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++)
        {
            if (!perform_crypto_operation(crypto_ctx, encrypted.data(), decrypted.data(),
                                          padded_size, iv, false))
            {
                std::cerr << "Decryption failed at iteration " << i << std::endl;
                break;
            }
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        bool verification_success = true;
        for (size_t i = 0; i < filesize; i++)
        {
            if (buffer[i] != decrypted[i])
            {
                verification_success = false;
                break;
            }
        }
        FILE *enc_fp = fopen("encrypted.bin", "wb");
        if (enc_fp)
        {
            fwrite(encrypted.data(), 1, padded_size, enc_fp);
            fclose(enc_fp);
        }
        else
        {
            std::cerr << "Failed to create encrypted file" << std::endl;
        }
        FILE *dec_fp = fopen(decrypted_filename.c_str(), "wb");
        if (dec_fp)
        {
            fwrite(decrypted.data(), 1, filesize, dec_fp);
            fclose(dec_fp);
        }
        else
        {
            std::cerr << "Failed to create decrypted file" << std::endl;
        }
        sampling.store(false);
        cpu_sampling.store(true);
        if (power_sampling_enabled)
        {
            if (!join_thread_with_timeout(pwr_thread, 5000))
            {
                std::cerr << "Power thread failed to join" << std::endl;
            }
        }
        if (!join_thread_with_timeout(cpu_thread, 5000))
        {
            std::cerr << "CPU thread failed to join" << std::endl;
        }
        double encrypt_time_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        double decrypt_time_us = std::chrono::duration<double, std::micro>(t2 - t1).count();
        double total_time_ms = std::chrono::duration<double, std::milli>(t2 - t0).count();
        double total_data_mb = (filesize * iterations) / (1024.0 * 1024.0);
        double enc_mb_per_s = total_data_mb / (encrypt_time_us / 1000000.0);
        double dec_mb_per_s = total_data_mb / (decrypt_time_us / 1000000.0);
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
        double avg_curr = sample_count ? current_sum / sample_count : 0;
        double avg_volt = sample_count ? voltage_sum / sample_count : 0;
        double avg_cpu = cpu_usage_samples.empty() ? 0 : cpu_sum / cpu_usage_samples.size();
        double dur_s = total_time_ms / 1000.0;
        double energy_j = avg_p * dur_s;
        std::cout << "\n==========================================\n";
        std::cout << "      IMAGE PROCESSING RESULTS (" << iterations << " iterations)     \n";
        std::cout << "==========================================\n";
        std::cout << "File: " << filename << "\n";
        std::cout << "Size: " << filesize << " bytes (" << (filesize / 1024.0) << " KB)\n";
        std::cout << "Total data processed: " << (filesize * iterations) << " bytes ("
                  << total_data_mb << " MB)\n";
        std::cout << "Verification: " << (verification_success ? "✅ Success - Decryption verified" : "❌ Failed - Data mismatch") << "\n";
        std::cout << "\nPerformance:\n";
        std::cout << "Encryption time: " << encrypt_time_us << " µs (" << (encrypt_time_us / 1000.0) << " ms)\n";
        std::cout << "Decryption time: " << decrypt_time_us << " µs (" << (decrypt_time_us / 1000.0) << " ms)\n";
        std::cout << "Total processing time: " << total_time_ms << " ms\n";
        std::cout << "Average time per iteration:\n";
        std::cout << "  Encryption: " << (encrypt_time_us / iterations) << " µs\n";
        std::cout << "  Decryption: " << (decrypt_time_us / iterations) << " µs\n";
        std::cout << "Throughput (encryption): " << enc_mb_per_s << " MB/s\n";
        std::cout << "Throughput (decryption): " << dec_mb_per_s << " MB/s\n";
        std::cout << "\nPower metrics:\n";
        std::cout << "Current: " << (avg_curr * 1000000.0) << " μA\n";
        std::cout << "Voltage: " << avg_volt << " V\n";
        std::cout << "Power: " << (avg_p * 1000.0) << " mW (" << avg_p << " W)\n";
        std::cout << "Energy consumption: " << (energy_j * 1000.0) << " mJ (" << energy_j << " J)\n";
        std::cout << "Energy per byte: " << ((energy_j * 1000000.0) / (filesize * iterations)) << " μJ/byte\n";
        std::cout << "\nOutput files:\n";
        std::cout << "Encrypted file saved as: encrypted.bin\n";
        std::cout << "Decrypted file saved as: " << decrypted_filename << "\n";
        std::cout << "==========================================\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Crypto operation failed: " << e.what() << std::endl;
        sampling.store(false);
        cpu_sampling.store(false);
        if (power_sampling_enabled)
            join_thread_with_timeout(pwr_thread, 5000);
        join_thread_with_timeout(cpu_thread, 5000);
    }
}

void runBenchmark(size_t iterations, const std::string &plain, const char *hwmon_path)
{
    pin_to_core(0);
    bool power_sampling_enabled = ina.begin();
    if (!power_sampling_enabled)
    {
        std::cerr << "Warning: Power and current sampling disabled due to INA219 failure\n";
    }
    const size_t BLOCK_SIZE = 16, KEY_SIZE = 32;
    size_t data_len = plain.size(),
           pad_len = ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    std::vector<uint8_t> pt(pad_len, 0), ct(pad_len), dt(pad_len);
    memcpy(pt.data(), plain.data(), data_len);
    uint8_t key[KEY_SIZE], iv[BLOCK_SIZE] = {0};
    for (size_t i = 0; i < KEY_SIZE; i++)
        key[i] = uint8_t(i);
    power_samples.reserve(1000);
    current_samples.reserve(1000);
    voltage_samples.reserve(1000);
    cpu_usage_samples.reserve(1000);
    std::cout << "\n==========================================\n";
    std::cout << "         BENCHMARK STARTED                \n";
    std::cout << "==========================================\n";
    std::cout << "Starting AES-CBC benchmark with " << iterations << " repetitions...\n";
    std::cout << "Input: \"" << plain << "\" (" << data_len << " bytes, padded to " << pad_len << " bytes)\n";
    std::thread pwr_thread;
    if (power_sampling_enabled)
    {
        sampling.store(true);
        pwr_thread = std::thread(power_thread_fn);
    }
    cpu_sampling.store(true);
    std::thread cpu_thread(cpu_thread_fn);
    auto t0 = std::chrono::high_resolution_clock::now();
    try
    {
        CryptoContext crypto_ctx("cbc(aes)", key, KEY_SIZE);
        if (crypto_ctx.use_fallback)
        {
            std::cout << "[INFO] Using OpenSSL software AES-CBC (CAAM not available)\n";
        }
        else
        {
            std::cout << "[INFO] Using CAAM hardware acceleration for AES-CBC\n";
        }
        for (size_t it = 0; it < iterations; ++it)
        {
            if (!perform_crypto_operation(crypto_ctx, pt.data(), ct.data(), pad_len, iv, true))
            {
                std::cerr << "Encryption failed at iteration " << it << std::endl;
                break;
            }
            if (it > 0 && it % 1000 == 0)
            {
                std::cout << ".";
                std::cout.flush();
                if (it % 10000 == 0)
                {
                    std::cout << " " << it << " repetitions completed\n";
                }
            }
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        for (size_t it = 0; it < iterations; ++it)
        {
            if (!perform_crypto_operation(crypto_ctx, ct.data(), dt.data(), pad_len, iv, false))
            {
                std::cerr << "Decryption failed at iteration " << it << std::endl;
                break;
            }
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
        double total_time_ms = std::chrono::duration<double, std::milli>(t3 - t0).count();
        double latency_e = iterations ? enc_us / iterations : 0;
        double latency_d = iterations ? dec_us / iterations : 0;
        double tp_e = latency_e ? (pad_len * 1e6) / latency_e : 0;
        double tp_d = latency_d ? (pad_len * 1e6) / latency_d : 0;
        double goodput_e = latency_e ? (data_len * 1e6) / latency_e : 0;
        double goodput_d = latency_d ? (data_len * 1e6) / latency_d : 0;
        float protocol_overhead_pct = 100.0 * (1.0 - ((float)data_len / pad_len));
        long ram = ru_end.ru_maxrss * 1024;
        std::cout << "\n==========================================\n";
        std::cout << "         POWER MEASUREMENTS              \n";
        std::cout << "==========================================\n";
        std::cout << "Average current: " << (avg_curr_A * 1000000.0) << " μA (" << avg_curr_A << " A)\n";
        std::cout << "Bus voltage: " << avg_volt_V << " V\n";
        std::cout << "Average power: " << (avg_p * 1000.0) << " mW (" << avg_p << " W)\n";
        std::cout << "Energy consumption: " << (e_J * 1000.0) << " mJ (" << e_J << " J)\n";
        std::cout << "Energy in watt-hours: " << (e_J / 3600.0) << " Wh\n";
        std::cout << "Energy per operation: " << (e_J * 1000.0 / iterations) << " mJ/op\n";
        std::cout << "Energy per byte: " << ((e_J * 1000000.0) / (iterations * pad_len)) << " μJ/byte\n";
        std::cout << "\n==========================================\n";
        std::cout << "         BENCHMARK RESULTS               \n";
        std::cout << "==========================================\n";
        std::cout << "Input text: \"" << plain << "\" (" << data_len << " bytes, padded to " << pad_len << " bytes)\n";
        std::cout << "Total encryption time: " << enc_us << " µs\n";
        std::cout << "Total decryption time: " << dec_us << " µs\n";
        std::cout << "Total combined time: " << (enc_us + dec_us) << " µs\n";
        std::cout << "Total benchmark time: " << total_time_ms << " ms\n";
        std::cout << "CPU usage: " << avg_cpu << "%\n";
        std::cout << "\nAverage time per operation:\n";
        std::cout << "  Encryption: " << latency_e << " µs\n";
        std::cout << "  Decryption: " << latency_d << " µs\n";
        std::cout << "  Combined average: " << ((latency_e + latency_d) / 2.0) << " µs\n";
        std::cout << "\nPerformance metrics:\n";
        std::cout << "Encryption throughput: " << tp_e << " bytes/s\n";
        std::cout << "Decryption throughput: " << tp_d << " bytes/s\n";
        std::cout << "Encryption goodput: " << goodput_e << " bytes/s\n";
        std::cout << "Decryption goodput: " << goodput_d << " bytes/s\n";
        std::cout << "Protocol overhead: " << protocol_overhead_pct << "%\n";
        std::cout << "\nResource usage:\n";
        std::cout << "Peak RAM: " << ram << " bytes\n";
        std::cout << "Program size: " << program_size << " bytes\n";
        verify_decryption(pt, dt, data_len);
        std::string decrypted;
        for (size_t i = 0; i < data_len; ++i)
            if (dt[i] >= 32 && dt[i] <= 126)
                decrypted += static_cast<char>(dt[i]);
        if (decrypted.size() > 2 && decrypted.substr(decrypted.size() - 2) == "=?")
        {
            std::string expr = decrypted.substr(0, decrypted.size() - 2);
            if (!expr.empty())
            {
                try
                {
                    double result = eval_expr(expr);
                    std::cout << "RESP:RESULT=" << (int)result << "\n";
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Expression evaluation error: " << e.what() << "\n";
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Crypto operation failed: " << e.what() << std::endl;
        sampling.store(false);
        cpu_sampling.store(false);
        if (power_sampling_enabled)
            join_thread_with_timeout(pwr_thread, 5000);
        join_thread_with_timeout(cpu_thread, 5000);
    }
}

int main(int argc, char *argv[])
{
    const char *hwmon_path = DEFAULT_HWMON_PATH;
    size_t iterations = 0;
    std::string plain;
    bool run_image_test = false;
    std::string image_filename;
    if (argc >= 3)
    {
        std::string cmd = argv[1];
        if (cmd == "REPEAT" && argc >= 4)
        {
            try
            {
                iterations = std::stoul(argv[2]);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Invalid iterations: " << argv[2] << "\n";
                return 1;
            }
            plain.clear();
            for (int i = 3; i < argc; i++)
            {
                if (i > 3)
                    plain += " ";
                plain += argv[i];
            }
            if (const char *env_hwmon = std::getenv("HWMON_PATH"))
            {
                hwmon_path = env_hwmon;
            }
            runBenchmark(iterations, plain, hwmon_path);
        }
        else if (cmd == "REPEAT_image" && argc >= 4)
        {
            try
            {
                iterations = std::stoul(argv[2]);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Invalid iterations: " << argv[2] << "\n";
                return 1;
            }
            image_filename = argv[3];
            std::cout << "\n==========================================\n";
            std::cout << "         IMAGE BENCHMARK STARTED          \n";
            std::cout << "==========================================\n";
            std::cout << "Starting image benchmark with " << iterations << " repetitions...\n";
            std::cout << "Image file: " << image_filename << "\n";
            processImageFile(image_filename.c_str(), iterations);
            return 0;
        }
        else if (argc >= 3 && strcmp(argv[2], "-image") == 0)
        {
            image_filename = argv[1];
            processImageFile(image_filename.c_str(), 1);
            return 0;
        }
        else
        {
            try
            {
                iterations = std::stoul(argv[1]);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Invalid iterations: " << argv[1] << "\n";
                return 1;
            }
            plain = argv[2];
            if (argc >= 4)
            {
                hwmon_path = argv[3];
            }
            else if (const char *env_hwmon = std::getenv("HWMON_PATH"))
            {
                hwmon_path = env_hwmon;
            }
            runBenchmark(iterations, plain, hwmon_path);
        }
    }
    else
    {
        std::cerr << "Usage: " << argv[0] << " <iterations> <plaintext> [<hwmon_path>]\n";
        std::cerr << "   or: " << argv[0] << " REPEAT <iterations> <plaintext>\n";
        std::cerr << "   or: " << argv[0] << " REPEAT_image <iterations> <filename>\n";
        std::cerr << "   or: " << argv[0] << " <image_filename> -image\n";
        return 1;
    }
    return 0;
}