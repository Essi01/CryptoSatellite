// benchmark.c (Disk I/O-fokusert for sammenligning mellom Portenta X8 og Toradex)
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <sys/time.h>
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <math.h>
#include "ascon.h"
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

// Constants
#define INA226_ADDRESS 0x40
#define INA226_REG_CONFIG 0x00
#define INA226_REG_SHUNT_VOLTAGE 0x01
#define INA226_REG_BUS_VOLTAGE 0x02
#define INA226_REG_POWER 0x03
#define INA226_REG_CURRENT 0x04
#define INA226_REG_CALIBRATION 0x05
#define INA226_CURRENT_LSB 0.0001f
#define INA226_POWER_LSB (25.0f * INA226_CURRENT_LSB)

#define MAX_SIZE 256
#define POWER_SAMPLE_COUNT 1000

// Thread-specific defines
#define POWER_THREAD_CORE 0
#define CPU_THREAD_CORE 1
#define CRYPTO_THREAD_CORE 2

// Global variables
volatile bool threads_running = true;
bool benchmark_running = false;
unsigned char benchmark_padded[MAX_SIZE] = {0};
unsigned char benchmark_encrypted[MAX_SIZE + IV_SIZE + TAG_SIZE] = {0};
unsigned char benchmark_decrypted[MAX_SIZE] = {0};
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_total_iterations = 0;
long benchmark_current_iteration = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_total_read_time = 0;  // Ny for disk I/O
unsigned long benchmark_total_write_time = 0; // Ny for disk I/O
unsigned long benchmark_start_time = 0;
char benchmark_text[MAX_SIZE] = "";

// Thread variables
pthread_t power_thread_id, cpu_thread_id;
pthread_mutex_t power_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

// Power measurement variables
typedef struct {
    unsigned long timestamp;
    float current_mA;
    float voltage_V;
    float power_mW;
} PowerSample;
PowerSample power_samples[POWER_SAMPLE_COUNT];
int power_sample_count = 0;
float benchmark_total_energy = 0.0;
float benchmark_avg_current = 0.0;
float benchmark_max_current = 0.0;
float benchmark_min_current = 9999.0;

// CPU measurement variables
typedef struct {
    unsigned long timestamp;
    float cpu_usage_percent;
} CpuSample;
CpuSample cpu_samples[POWER_SAMPLE_COUNT];
int cpu_sample_count = 0;
float cpu_usage = 0.0;
float crypto_core_usage = 0.0;
float max_crypto_usage = 0.0;

// I2C file descriptor
int i2c_fd = -1;

// Function prototypes
unsigned long get_time_ms(void);
unsigned long safe_time_diff(unsigned long start, unsigned long end);
bool write_ina226_register(uint8_t reg, uint16_t value);
bool read_ina226_register(uint8_t reg, uint16_t *value);
bool read_ina226_measurements(float *power_W, float *current_A, float *voltage_V);
void init_ina226(void);
void close_ina226(void);
void set_thread_affinity(pthread_t thread, int core_id);
void *power_monitoring_thread(void *arg);
void *cpu_monitoring_thread(void *arg);
void measure_memory(const char* label);
void read_power_measurements(void);
void run_benchmark(const char* text, long iterations);
void process_image_file_with_disk_io(const char* filename, int iterations);
void init_threads(void);
void cleanup_threads(void);
void signal_handler(int sig);

// Get time in milliseconds
unsigned long get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000UL);
}

// Safe time difference calculation to handle timer overflow
unsigned long safe_time_diff(unsigned long start, unsigned long end) {
    return (end >= start) ? (end - start) : ((ULONG_MAX - start) + end + 1);
}

// Write to INA226 register
bool write_ina226_register(uint8_t reg, uint16_t value) {
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
    
    if (ioctl(i2c_fd, I2C_RDWR, &packets) < 0) {
        return false;
    }
    
    return true;
}

// Read from INA226 register
bool read_ina226_register(uint8_t reg, uint16_t *value) {
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
    
    if (ioctl(i2c_fd, I2C_RDWR, &packets) < 0) {
        return false;
    }
    
    *value = (data[0] << 8) | data[1];
    return true;
}

// Read power measurements from INA226
bool read_ina226_measurements(float *power_W, float *current_A, float *voltage_V) {
    if (i2c_fd < 0) {
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    
    uint16_t bus_voltage_raw;
    if (!read_ina226_register(INA226_REG_BUS_VOLTAGE, &bus_voltage_raw)) {
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *voltage_V = bus_voltage_raw * 0.00125f;
    
    uint16_t current_raw;
    if (!read_ina226_register(INA226_REG_CURRENT, &current_raw)) {
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *current_A = (int16_t)current_raw * INA226_CURRENT_LSB;
    
    uint16_t power_raw;
    if (!read_ina226_register(INA226_REG_POWER, &power_raw)) {
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *power_W = power_raw * INA226_POWER_LSB;
    
    return true;
}

// Initialize INA226 power monitor
void init_ina226(void) {
    const char* device_path = "/dev/i2c-3";
    
    pthread_mutex_lock(&print_mutex);
    printf("Initializing INA226 on %s for crypto model\n", device_path);
    pthread_mutex_unlock(&print_mutex);
    
    i2c_fd = open(device_path, O_RDWR);
    if (i2c_fd < 0) {
        pthread_mutex_lock(&print_mutex);
        printf("[ERROR] Cannot open I2C device %s: %s\n", device_path, strerror(errno));
        pthread_mutex_unlock(&print_mutex);
        return;
    }
    
    if (ioctl(i2c_fd, I2C_SLAVE, INA226_ADDRESS) < 0) {
        pthread_mutex_lock(&print_mutex);
        printf("[ERROR] Failed to set INA226 I2C slave address: %s\n", strerror(errno));
        pthread_mutex_unlock(&print_mutex);
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    pthread_mutex_lock(&print_mutex);
    printf("Successfully opened INA226 on %s at address 0x%02X\n", device_path, INA226_ADDRESS);
    pthread_mutex_unlock(&print_mutex);
    
    // Configure INA226: Average 16 samples, 1.1ms conversion, continuous mode
    uint16_t config = (0x4 << 12) | (0x4 << 9) | (0x4 << 6) | (0x4 << 3) | (0x7);
    if (!write_ina226_register(INA226_REG_CONFIG, config)) {
        pthread_mutex_lock(&print_mutex);
        printf("[ERROR] Failed to configure INA226\n");
        pthread_mutex_unlock(&print_mutex);
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Set calibration register
    uint16_t calibration = 512;
    if (!write_ina226_register(INA226_REG_CALIBRATION, calibration)) {
        pthread_mutex_lock(&print_mutex);
        printf("[ERROR] Failed to set INA226 calibration\n");
        pthread_mutex_unlock(&print_mutex);
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Verify configuration
    uint16_t readback_config;
    if (read_ina226_register(INA226_REG_CONFIG, &readback_config)) {
        pthread_mutex_lock(&print_mutex);
        printf("[INFO] INA226 config verification: 0x%04X\n", readback_config);
        if (readback_config == config) {
            printf("[SUCCESS] INA226 configuration verified!\n");
        } else {
            printf("[WARNING] Configuration mismatch: expected 0x%04X, got 0x%04X\n", config, readback_config);
        }
        pthread_mutex_unlock(&print_mutex);
    }
    
    // Read initial values
    float power_W, current_A, voltage_V;
    if (read_ina226_measurements(&power_W, &current_A, &voltage_V)) {
        pthread_mutex_lock(&print_mutex);
        printf("[INFO] Initial readings - Current: %.2f mA, Voltage: %.3f V, Power: %.2f mW\n",
               current_A * 1000.0f, voltage_V, power_W * 1000.0f);
        pthread_mutex_unlock(&print_mutex);
    }
    
    pthread_mutex_lock(&print_mutex);
    printf("[INFO] INA226 initialization with crypto model complete\n");
    pthread_mutex_unlock(&print_mutex);
}

// Close INA226 connection
void close_ina226(void) {
    if (i2c_fd >= 0) {
        close(i2c_fd);
        i2c_fd = -1;
    }
}

// Set thread affinity to specific core
void set_thread_affinity(pthread_t thread, int core_id) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(core_id, &cpus);
    
    if (pthread_setaffinity_np(thread, sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin thread to core %d: %s\n", core_id, strerror(errno));
        pthread_mutex_unlock(&print_mutex);
    } else {
        pthread_mutex_lock(&print_mutex);
        printf("Thread affinity setting - pinning thread to core %d\n", core_id);
        pthread_mutex_unlock(&print_mutex);
    }
}

// Power monitoring thread
void *power_monitoring_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("Power monitoring thread started on core %d\n", POWER_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    // Set thread affinity
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(POWER_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin power thread to core %d\n", POWER_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    while (threads_running) {
        float power_W, current_A, voltage_V;
        bool valid_reading = read_ina226_measurements(&power_W, &current_A, &voltage_V);
        
        if (valid_reading) {
            unsigned long now = get_time_ms();
            float current_mA = current_A * 1000.0f;
            float power_mW = power_W * 1000.0f;
            
            pthread_mutex_lock(&power_mutex);
            if (power_sample_count < POWER_SAMPLE_COUNT) {
                power_samples[power_sample_count].timestamp = now;
                power_samples[power_sample_count].current_mA = current_mA;
                power_samples[power_sample_count].voltage_V = voltage_V;
                power_samples[power_sample_count].power_mW = power_mW;
                power_sample_count++;
                
                if (current_mA > benchmark_max_current) benchmark_max_current = current_mA;
                if (current_mA < benchmark_min_current && current_mA > 0) benchmark_min_current = current_mA;
            } else {
                memmove(&power_samples[0], &power_samples[1], 
                        (POWER_SAMPLE_COUNT - 1) * sizeof(PowerSample));
                
                power_samples[POWER_SAMPLE_COUNT - 1].timestamp = now;
                power_samples[POWER_SAMPLE_COUNT - 1].current_mA = current_mA;
                power_samples[POWER_SAMPLE_COUNT - 1].voltage_V = voltage_V;
                power_samples[POWER_SAMPLE_COUNT - 1].power_mW = power_mW;
                
                if (current_mA > benchmark_max_current) benchmark_max_current = current_mA;
                if (current_mA < benchmark_min_current && current_mA > 0) benchmark_min_current = current_mA;
            }
            pthread_mutex_unlock(&power_mutex);
            
            benchmark_avg_current += current_mA;
        }
        
        usleep(50000); // 50ms delay between samples
    }
    
    return NULL;
}

// CPU monitoring thread
void *cpu_monitoring_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("CPU monitoring thread started on core %d\n", CPU_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    // Set thread affinity
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(CPU_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin CPU thread to core %d\n", CPU_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    unsigned long long prev_total = 0, prev_idle = 0;
    unsigned long long prev_core_total = 0, prev_core_idle = 0;
    
    while (threads_running) {
        FILE *fp = fopen("/proc/stat", "r");
        if (fp == NULL) {
            usleep(100000);
            continue;
        }
        
        // Read overall CPU stats
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), fp)) {
            unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
            sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", 
                   &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
            
            unsigned long long total_time = user + nice + system + idle + iowait + irq + softirq + steal;
            unsigned long long idle_time = idle + iowait;
            
            if (prev_total > 0 && prev_idle > 0) {
                unsigned long long total_delta = total_time - prev_total;
                unsigned long long idle_delta = idle_time - prev_idle;
                
                if (total_delta > 0) {
                    float cpu_percent = 100.0 * (1.0 - ((float)idle_delta / total_delta));
                    unsigned long now = get_time_ms();
                    
                    pthread_mutex_lock(&cpu_mutex);
                    if (cpu_sample_count < POWER_SAMPLE_COUNT) {
                        cpu_samples[cpu_sample_count].timestamp = now;
                        cpu_samples[cpu_sample_count].cpu_usage_percent = cpu_percent;
                        cpu_sample_count++;
                    } else {
                        memmove(&cpu_samples[0], &cpu_samples[1], 
                                (POWER_SAMPLE_COUNT - 1) * sizeof(CpuSample));
                        cpu_samples[POWER_SAMPLE_COUNT - 1].timestamp = now;
                        cpu_samples[POWER_SAMPLE_COUNT - 1].cpu_usage_percent = cpu_percent;
                    }
                    pthread_mutex_unlock(&cpu_mutex);
                }
            }
            
            prev_total = total_time;
            prev_idle = idle_time;
        }
        
        // Read crypto core (CPU2) stats
        rewind(fp);
        // Skip overall CPU line
        fgets(buffer, sizeof(buffer), fp);
        
        // Read each core until we reach the crypto core
        char core_line[256];
        for (int i = 0; i <= CRYPTO_THREAD_CORE; i++) {
            if (fgets(core_line, sizeof(core_line), fp) == NULL) {
                break;
            }
            
            if (i == CRYPTO_THREAD_CORE) {
                unsigned long long c_user, c_nice, c_system, c_idle, c_iowait, c_irq, c_softirq, c_steal;
                int core_num;
                sscanf(core_line, "cpu%d %llu %llu %llu %llu %llu %llu %llu %llu", 
                       &core_num, &c_user, &c_nice, &c_system, &c_idle, 
                       &c_iowait, &c_irq, &c_softirq, &c_steal);
                
                unsigned long long core_total = c_user + c_nice + c_system + c_idle + 
                                              c_iowait + c_irq + c_softirq + c_steal;
                unsigned long long core_idle = c_idle + c_iowait;
                
                if (prev_core_total > 0 && prev_core_idle > 0) {
                    unsigned long long core_total_delta = core_total - prev_core_total;
                    unsigned long long core_idle_delta = core_idle - prev_core_idle;
                    
                    if (core_total_delta > 0) {
                        float core_cpu_percent = 100.0 * (1.0 - ((float)core_idle_delta / core_total_delta));
                        
                        pthread_mutex_lock(&cpu_mutex);
                        crypto_core_usage = core_cpu_percent;
                        if (core_cpu_percent > max_crypto_usage) {
                            max_crypto_usage = core_cpu_percent;
                        }
                        pthread_mutex_unlock(&cpu_mutex);
                    }
                }
                
                prev_core_total = core_total;
                prev_core_idle = core_idle;
            }
        }
        
        fclose(fp);
        usleep(100000); // 100ms delay
    }
    
    return NULL;
}

// Memory measurement function
void measure_memory(const char* label) {
    FILE* fp;
    char buffer[1024];
    unsigned long mem_total = 0;
    unsigned long mem_free = 0;
    unsigned long mem_available = 0;
    
    fp = fopen("/proc/meminfo", "r");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if (strncmp(buffer, "MemTotal:", 9) == 0) {
                sscanf(buffer, "MemTotal: %lu kB", &mem_total);
            } else if (strncmp(buffer, "MemFree:", 8) == 0) {
                sscanf(buffer, "MemFree: %lu kB", &mem_free);
            } else if (strncmp(buffer, "MemAvailable:", 13) == 0) {
                sscanf(buffer, "MemAvailable: %lu kB", &mem_available);
            }
        }
        fclose(fp);
    }
    
    // Calculate used memory
    unsigned long used_ram = mem_total - mem_available;
    
    pthread_mutex_lock(&print_mutex);
    printf("MEMORY [%s]: Total: %lu kB, Used: %lu kB, Free: %lu kB\n", 
           label, mem_total, used_ram, mem_available);
    pthread_mutex_unlock(&print_mutex);
}

// Read and display power measurements
void read_power_measurements(void) {
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    float avg_power = 0.0;
    float avg_voltage = 0.0;
    
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
            avg_voltage += power_samples[i].voltage_V;
            avg_power += power_samples[i].power_mW;
        }
        avg_current /= power_sample_count;
        avg_voltage /= power_sample_count;
        avg_power /= power_sample_count;
    }
    
    // Get latest sample
    float current = 0.0;
    float voltage = 0.0;
    float power = 0.0;
    
    if (power_sample_count > 0) {
        current = power_samples[power_sample_count - 1].current_mA;
        voltage = power_samples[power_sample_count - 1].voltage_V;
        power = power_samples[power_sample_count - 1].power_mW;
    }
    pthread_mutex_unlock(&power_mutex);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         POWER MEASUREMENTS              \n");
    printf("==========================================\n");
    printf("Current (instant): %.2f mA\n", current);
    printf("Current (average): %.2f mA\n", avg_current);
    printf("Bus Voltage: %.3f V\n", voltage);
    printf("Power (instant): %.2f mW (%.3f W)\n", power, power / 1000.0);
    printf("Power (average): %.2f mW (%.3f W)\n", avg_power, avg_power / 1000.0);
    printf("Samples: %d\n", power_sample_count);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
    
    pthread_mutex_lock(&cpu_mutex);
    float avg_cpu = 0.0;
    
    if (cpu_sample_count > 0) {
        for (int i = 0; i < cpu_sample_count; i++) {
            avg_cpu += cpu_samples[i].cpu_usage_percent;
        }
        avg_cpu /= cpu_sample_count;
    }
    
    float crypto_current = crypto_core_usage;
    pthread_mutex_unlock(&cpu_mutex);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         CPU MEASUREMENTS                \n");
    printf("==========================================\n");
    printf("CPU Usage (average): %.2f%%\n", avg_cpu);
    printf("Crypto Core Usage: %.2f%%\n", crypto_current);
    printf("Samples: %d\n", cpu_sample_count);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
}

// Run benchmark on text data
void run_benchmark(const char* text, long iterations) {
    // Measure memory before benchmark
    measure_memory("Before Benchmark");
    
    // Copy text
    strncpy(benchmark_text, text, MAX_SIZE - 1);
    benchmark_text[MAX_SIZE - 1] = '\0';
    benchmark_input_len = strlen(text);
    
    if (benchmark_input_len == 0 || benchmark_input_len > MAX_SIZE - 16) {
        pthread_mutex_lock(&print_mutex);
        printf("Invalid text length\n");
        pthread_mutex_unlock(&print_mutex);
        return;
    }
    
    // Perform padding once before repetitions
    benchmark_padded_len = padData(text, benchmark_padded, benchmark_input_len);
    
    // Reset all counters
    benchmark_current_iteration = 0;
    benchmark_total_iterations = iterations;
    benchmark_total_encrypt_time = 0;
    benchmark_total_decrypt_time = 0;
    
    // Reset power measurements
    pthread_mutex_lock(&power_mutex);
    power_sample_count = 0;
    benchmark_total_energy = 0.0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    pthread_mutex_unlock(&power_mutex);
    
    // Reset CPU measurements
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = 0.0;
    max_crypto_usage = 0.0;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Start timing for the entire benchmark
    benchmark_start_time = get_time_ms();
    
    // Set benchmark state to running
    benchmark_running = true;
    
    // Pin main thread to crypto core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(CRYPTO_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin main thread to core %d\n", CRYPTO_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         BENCHMARK STARTED                \n");
    printf("==========================================\n");
    printf("Starting Ascon AEAD benchmark with %ld repetitions...\n", iterations);
    printf("Input: \"%s\" (%zu bytes, padded to %zu bytes)\n", 
           text, benchmark_input_len, benchmark_padded_len);
    printf("(You can send new commands while benchmark is running)\n");
    printf("Send 'STOP' to abort benchmark\n");
    pthread_mutex_unlock(&print_mutex);
    
    // Run encryption operations
    for (long i = 0; i < iterations && benchmark_running; i++) {
        // Encryption timing
        struct timeval start_tv, end_tv;
        gettimeofday(&start_tv, NULL);
        encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
        gettimeofday(&end_tv, NULL);
        unsigned long encrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        benchmark_total_encrypt_time += encrypt_time;
        
        // Decryption timing
        gettimeofday(&start_tv, NULL);
        decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len + IV_SIZE + TAG_SIZE);
        gettimeofday(&end_tv, NULL);
        unsigned long decrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        benchmark_total_decrypt_time += decrypt_time;
        
        // Increase iteration counter
        benchmark_current_iteration++;
        
        // Show progress
        if (i % 100 == 0 || i == iterations - 1) {
            pthread_mutex_lock(&print_mutex);
            printf(".");
            fflush(stdout);
            if (i % 1000 == 0 && i > 0) {
                printf(" %ld iterations (%.1f%%)\n", i, (float)i/iterations*100);
                fflush(stdout);
            }
            pthread_mutex_unlock(&print_mutex);
        }
    }
    
    pthread_mutex_lock(&print_mutex);
    printf("\nBenchmark complete.\n");
    pthread_mutex_unlock(&print_mutex);
    
    // End timing for the entire benchmark
    unsigned long benchmark_end = get_time_ms();
    unsigned long total_benchmark_time = safe_time_diff(benchmark_start_time, benchmark_end);
    
    // Calculate CPU usage for crypto operations
    float crypto_time_ms = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0;
    float wall_time_ms = total_benchmark_time;
    float time_efficiency = (crypto_time_ms / wall_time_ms) * 100.0;
    
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = time_efficiency;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Handle power measurements
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    float avg_voltage = 0.0;
    float avg_power = 0.0;
    
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
            avg_voltage += power_samples[i].voltage_V;
            avg_power += power_samples[i].power_mW;
        }
        avg_current /= power_sample_count;
        avg_voltage /= power_sample_count;
        avg_power /= power_sample_count;
        benchmark_avg_current = avg_current;
    }
    pthread_mutex_unlock(&power_mutex);
    
    // Calculate energy metrics
    float avg_power_w = avg_power / 1000.0;
    float energy_mj = avg_power * (total_benchmark_time / 1000.0);
    float energy_j = energy_mj / 1000.0;
    float energy_wh = energy_mj / 3600000.0;
    float per_byte_energy = energy_mj / (benchmark_total_iterations * benchmark_padded_len);
    float crypto_energy_mj = (crypto_time_ms / 1000.0) * avg_power;
    
    // Calculate performance metrics
    float avg_enc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
    float avg_dec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;
    unsigned long total_combined_time = benchmark_total_encrypt_time + benchmark_total_decrypt_time;
    float combined_average = total_combined_time / (float)(benchmark_total_iterations * 2);
    
    unsigned long enc_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avg_enc);
    unsigned long dec_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avg_dec);
    unsigned long enc_goodput = (unsigned long)(benchmark_input_len * 1e6 / avg_enc);
    unsigned long dec_goodput = (unsigned long)(benchmark_input_len * 1e6 / avg_dec);
    
    float protocol_overhead = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         BENCHMARK RESULTS               \n");
    printf("==========================================\n");
    printf("Input text: \"%s\" (%zu bytes, padded to %zu bytes)\n", 
           benchmark_text, benchmark_input_len, benchmark_padded_len);
    
    printf("Total encryption time: %lu µs\n", benchmark_total_encrypt_time);
    printf("Total decryption time: %lu µs\n", benchmark_total_decrypt_time);
    printf("Total combined time: %lu µs\n", total_combined_time);
    printf("Total benchmark time: %lu ms\n", total_benchmark_time);
    printf("Time efficiency: %.2f%% (crypto ops time / total time)\n", time_efficiency);
    printf("Crypto core usage: %.2f%%\n", crypto_core_usage);
    
    printf("\nAverage time per operation:\n");
    printf("  Encryption: %.2f µs\n", avg_enc);
    printf("  Decryption: %.2f µs\n", avg_dec);
    printf("  Combined average: %.2f µs\n", combined_average);
    
    printf("\nPerformance metrics:\n");
    printf("Encryption throughput: %lu bytes/s\n", enc_throughput);
    printf("Decryption throughput: %lu bytes/s\n", dec_throughput);
    printf("Encryption goodput: %lu bytes/s\n", enc_goodput);
    printf("Decryption goodput: %lu bytes/s\n", dec_goodput);
    printf("Protocol overhead: %.1f%%\n", protocol_overhead);
    
    printf("\n==========================================\n");
    printf("         POWER MEASUREMENTS              \n");
    printf("==========================================\n");
    printf("Average current: %.2f mA (%.6f A)\n", benchmark_avg_current, benchmark_avg_current / 1000.0);
    
    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
        printf("Current range: %.2f - %.2f mA\n", benchmark_min_current, benchmark_max_current);
    }
    
    printf("Bus voltage: %.3f V\n", avg_voltage);
    printf("Average power: %.2f mW (%.6f W)\n", avg_power, avg_power_w);
    printf("Energy consumption: %.2f mJ (%.6f J, %.8f Wh)\n", energy_mj, energy_j, energy_wh);
    printf("Energy per operation: %.6f mJ/op\n", energy_mj / benchmark_total_iterations);
    printf("Energy per byte: %.6f µJ/byte\n", per_byte_energy * 1000.0);
    printf("Crypto operations energy: %.2f mJ (%.2f%%)\n", crypto_energy_mj, 
           (crypto_energy_mj / energy_mj) * 100.0);
    
    printf("\n==========================================\n");
    printf("         DATA SAMPLES                    \n");
    printf("==========================================\n");
    printf("Encrypted (first block with IV): ");
    printHex(benchmark_encrypted, (benchmark_padded_len + IV_SIZE + TAG_SIZE < 32) ? 
             benchmark_padded_len + IV_SIZE + TAG_SIZE : 32);
    
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    printf("Decrypted: %s\n", benchmark_decrypted);
    
    if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
        strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
        int result = evaluerUttrykk((char*)benchmark_decrypted);
        if (result != 0) {
            printf("RESP:RESULT=%d\n", result);
        }
    }
    pthread_mutex_unlock(&print_mutex);
    
    // Add memory measurement at end
    measure_memory("After Benchmark");
    
    // End benchmark state
    benchmark_running = false;
}

// Process image file with ASCON encryption - med full disk I/O for hver iterasjon
void process_image_file_with_disk_io(const char* filename, int iterations) {
    // Reset measurements
    pthread_mutex_lock(&power_mutex);
    power_sample_count = 0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    pthread_mutex_unlock(&power_mutex);
    
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = 0.0;
    max_crypto_usage = 0.0;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Reset timings
    benchmark_total_read_time = 0;
    benchmark_total_write_time = 0;
    benchmark_total_encrypt_time = 0;
    benchmark_total_decrypt_time = 0;
    
    // Memory measurement
    measure_memory("Before Image Test");
    
    // Start timing
    benchmark_start_time = get_time_ms();
    
    // File info
    size_t filesize = 0;
    
    // Get file extension
    char file_extension[16] = ".jpg";
    const char *dot = strrchr(filename, '.');
    if (dot && strlen(dot) < 15) {
        strcpy(file_extension, dot);
    }
    
    // Create output filename
    char decrypted_filename[128] = "decrypted";
    strcat(decrypted_filename, file_extension);
    
    // Set benchmark state
    benchmark_running = true;
    
    // Pin main thread to crypto core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(CRYPTO_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin main thread to core %d\n", CRYPTO_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    pthread_mutex_lock(&print_mutex);
    printf("\nStarting image test with disk I/O for %s with %d iterations...\n", 
           filename, iterations);
    pthread_mutex_unlock(&print_mutex);
    
    struct timeval start_tv, end_tv;
    
    // Process image repeatedly
    for (int i = 0; i < iterations && benchmark_running; i++) {
        // Allocate memory for this iteration
        unsigned char *buffer = NULL;
        unsigned char *padded = NULL;
        unsigned char *encrypted = NULL;
        unsigned char *decrypted = NULL;
        
        // Read file timing
        gettimeofday(&start_tv, NULL);
        
        FILE *fp = fopen(filename, "rb");
        if (!fp) {
            pthread_mutex_lock(&print_mutex);
            printf("Failed to open file: %s (iteration %d)\n", filename, i);
            pthread_mutex_unlock(&print_mutex);
            continue;
        }
        
        // Get file size
        fseek(fp, 0, SEEK_END);
        filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        // Allocate memory
        buffer = malloc(filesize);
        padded = malloc(filesize + 16);
        encrypted = malloc(filesize + IV_SIZE + TAG_SIZE);
        decrypted = malloc(filesize + 16);
        
        if (!buffer || !padded || !encrypted || !decrypted) {
            pthread_mutex_lock(&print_mutex);
            printf("Memory allocation failed (iteration %d)\n", i);
            pthread_mutex_unlock(&print_mutex);
            fclose(fp);
            if (buffer) free(buffer);
            if (padded) free(padded);
            if (encrypted) free(encrypted);
            if (decrypted) free(decrypted);
            continue;
        }
        
        // Read file
        if (fread(buffer, 1, filesize, fp) != filesize) {
            pthread_mutex_lock(&print_mutex);
            printf("Failed to read entire file (iteration %d)\n", i);
            pthread_mutex_unlock(&print_mutex);
            fclose(fp);
            free(buffer);
            free(padded);
            free(encrypted);
            free(decrypted);
            continue;
        }
        fclose(fp);
        
        // End of read timing
        gettimeofday(&end_tv, NULL);
        unsigned long read_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                               (end_tv.tv_usec - start_tv.tv_usec);
        benchmark_total_read_time += read_time;
        
        // Perform padding
        size_t padded_len = padData((char*)buffer, padded, filesize);
        
        // Encrypt data
        gettimeofday(&start_tv, NULL);
        encrypt(padded, encrypted, padded_len);
        gettimeofday(&end_tv, NULL);
        unsigned long encrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        benchmark_total_encrypt_time += encrypt_time;
        
        // Decrypt data
        gettimeofday(&start_tv, NULL);
        decrypt(encrypted, decrypted, padded_len + IV_SIZE + TAG_SIZE);
        gettimeofday(&end_tv, NULL);
        unsigned long decrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        benchmark_total_decrypt_time += decrypt_time;
        
        // Write file timing (bare ved siste iterasjon)
        if (i == iterations-1) {
            gettimeofday(&start_tv, NULL);
            
            // Save encrypted file
            FILE *enc_fp = fopen("encrypted.bin", "wb");
            if (enc_fp) {
                fwrite(encrypted, 1, padded_len + IV_SIZE + TAG_SIZE, enc_fp);
                fclose(enc_fp);
            }
            
            // Save decrypted file
            FILE *dec_fp = fopen(decrypted_filename, "wb");
            if (dec_fp) {
                size_t actual_len = removePadding(decrypted, padded_len);
                fwrite(decrypted, 1, actual_len, dec_fp);
                fclose(dec_fp);
            }
            
            gettimeofday(&end_tv, NULL);
            unsigned long write_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                    (end_tv.tv_usec - start_tv.tv_usec);
            benchmark_total_write_time += write_time;
        }
        
        // Free memory for this iteration
        free(buffer);
        free(padded);
        free(encrypted);
        free(decrypted);
        
        // Show progress
        if (i % 10 == 0 || i == iterations-1) {
            pthread_mutex_lock(&print_mutex);
            printf(".");
            fflush(stdout);
            if (i % 100 == 0 && i > 0) {
                printf(" %d iterations (%.1f%%)\n", i, (float)i/iterations*100);
            }
            pthread_mutex_unlock(&print_mutex);
        }
    }
    
    // End timing
    unsigned long benchmark_end = get_time_ms();
    unsigned long total_time = safe_time_diff(benchmark_start_time, benchmark_end);
    
    // End benchmark state
    benchmark_running = false;
    
    // Calculate averages
    float avg_read_time = benchmark_total_read_time / (float)iterations;
    float avg_encrypt_time = benchmark_total_encrypt_time / (float)iterations;
    float avg_decrypt_time = benchmark_total_decrypt_time / (float)iterations;
    float avg_write_time = benchmark_total_write_time;  // Bare skrev én gang
    
    // Calculate throughputs
    float read_mb_per_s = (filesize * 1.0 / avg_read_time) * 1000000 / (1024*1024);
    float enc_mb_per_s = (filesize * 1.0 / avg_encrypt_time) * 1000000 / (1024*1024);
    float dec_mb_per_s = (filesize * 1.0 / avg_decrypt_time) * 1000000 / (1024*1024);
    float combined_mb_per_s = (filesize * iterations * 2.0) / ((benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000000.0) / (1024*1024);
    
    // Get power measurements
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    float avg_voltage = 0.0;
    float avg_power = 0.0;
    
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
            avg_voltage += power_samples[i].voltage_V;
            avg_power += power_samples[i].power_mW;
        }
        avg_current /= power_sample_count;
        avg_voltage /= power_sample_count;
        avg_power /= power_sample_count;
    }
    pthread_mutex_unlock(&power_mutex);
    
    // Get CPU usage
    pthread_mutex_lock(&cpu_mutex);
    float avg_cpu = 0.0;
    if (cpu_sample_count > 0) {
        for (int i = 0; i < cpu_sample_count; i++) {
            avg_cpu += cpu_samples[i].cpu_usage_percent;
        }
        avg_cpu /= cpu_sample_count;
    }
    float crypto_cpu = crypto_core_usage;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Calculate energy metrics
    float duration_s = total_time / 1000.0;
    float energy_mj = avg_power * duration_s;
    float energy_j = energy_mj / 1000.0;
    float energy_uj_per_byte = (energy_mj * 1000.0) / (filesize * iterations);
    
    // Memory measurement
    measure_memory("After Image Test");
    
    // Output results
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("   IMAGE TEST RESULTS WITH DISK I/O      \n");
    printf("==========================================\n");
    printf("File: %s\n", filename);
    printf("Size: %zu bytes (%.2f MB)\n", filesize, filesize / (1024.0*1024.0));
    printf("Iterations: %d\n", iterations);
    printf("Total data processed: %zu bytes (%.2f MB)\n", 
           filesize * iterations, filesize * iterations / (1024.0*1024.0));
    
    printf("\nTiming breakdown:\n");
    printf("Total file read time: %lu µs\n", benchmark_total_read_time);
    printf("Total encryption time: %lu µs\n", benchmark_total_encrypt_time);
    printf("Total decryption time: %lu µs\n", benchmark_total_decrypt_time);
    printf("Total file write time: %lu µs\n", benchmark_total_write_time);
    printf("Total processing time: %lu ms\n", total_time);
    
    printf("\nAverage times per operation:\n");
    printf("Average file read time: %.2f µs (%.2f ms)\n", avg_read_time, avg_read_time / 1000.0);
    printf("Average encryption time: %.2f µs (%.2f ms)\n", avg_encrypt_time, avg_encrypt_time / 1000.0);
    printf("Average decryption time: %.2f µs (%.2f ms)\n", avg_decrypt_time, avg_decrypt_time / 1000.0);
    printf("File write time: %.2f µs (%.2f ms)\n", avg_write_time, avg_write_time / 1000.0);
    
    printf("\nThroughput metrics:\n");
    printf("Disk read throughput: %.2f MB/s\n", read_mb_per_s);
    printf("Encryption throughput: %.2f MB/s\n", enc_mb_per_s);
    printf("Decryption throughput: %.2f MB/s\n", dec_mb_per_s);
    printf("Combined crypto throughput: %.2f MB/s\n", combined_mb_per_s);
    
    printf("\nPower metrics:\n");
    printf("Current: %.2f mA\n", avg_current);
    printf("Voltage: %.3f V\n", avg_voltage);
    printf("Power: %.2f mW (%.6f W)\n", avg_power, avg_power / 1000.0);
    printf("Energy consumption: %.2f mJ (%.6f J)\n", energy_mj, energy_j);
    printf("Energy per byte: %.2f µJ/byte\n", energy_uj_per_byte);
    printf("CPU usage: %.2f%% (crypto core: %.2f%%)\n", avg_cpu, crypto_cpu);
    
    printf("\nOutput files:\n");
    printf("Encrypted file saved as: encrypted.bin\n");
    printf("Decrypted file saved as: %s\n", decrypted_filename);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
}

// Initialize threads
void init_threads(void) {
    // Reset counters
    power_sample_count = 0;
    cpu_sample_count = 0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    threads_running = true;
    
    // Initialize INA226
    init_ina226();
    
    // Create power monitoring thread
    if (pthread_create(&power_thread_id, NULL, power_monitoring_thread, NULL) != 0) {
        printf("Error creating power monitoring thread\n");
        return;
    }
    
    // Create CPU monitoring thread
    if (pthread_create(&cpu_thread_id, NULL, cpu_monitoring_thread, NULL) != 0) {
        printf("Error creating CPU monitoring thread\n");
        return;
    }
    
    // Set thread affinity
    set_thread_affinity(power_thread_id, POWER_THREAD_CORE);
    set_thread_affinity(cpu_thread_id, CPU_THREAD_CORE);
    
    usleep(10000);
}

// Cleanup threads
void cleanup_threads(void) {
    // Signal threads to stop
    threads_running = false;
    
    // Wait for threads to finish
    pthread_join(power_thread_id, NULL);
    pthread_join(cpu_thread_id, NULL);
    
    // Close INA226
    close_ina226();
    
    pthread_mutex_lock(&print_mutex);
    printf("All threads terminated\n");
    pthread_mutex_unlock(&print_mutex);
}

// Signal handler for clean termination
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived Ctrl+C, cleaning up and exiting...\n");
        threads_running = false;
        benchmark_running = false;
        
        usleep(200000);
        
        cleanup_threads();
        exit(0);
    }
}

int main(int argc, char *argv[]) {
    // Initialize ASCON
    ascon_init();
    
    // Set up signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    // Initialize threads
    init_threads();
    
    measure_memory("Startup");
    
    printf("\n==========================================\n");
    printf("   ASCON Authenticated Encryption Test    \n");
    printf("==========================================\n");
    printf("Commands:\n");
    printf("  REPEAT [count] [text] - Run benchmark\n");
    printf("  IMAGE [count] [filename] - Process image with disk I/O\n");
    printf("  POWER - Read current power measurements\n");
    printf("  STOP - Abort running benchmark\n");
    printf("  Ctrl+C - Exit program\n");
    
    // Parse command line arguments if provided
    if (argc >= 2) {
        if (strcasecmp(argv[1], "REPEAT") == 0 && argc >= 4) {
            // REPEAT command format: REPEAT iterations text
            long iterations = atol(argv[2]);
            
            // Collect all remaining arguments as text
            char text[MAX_SIZE] = {0};
            for (int i = 3; i < argc; i++) {
                if (i > 3) strcat(text, " ");
                strcat(text, argv[i]);
            }
            
            // Run text benchmark
            run_benchmark(text, iterations);
            
            // Clean up and exit
            cleanup_threads();
            return 0;
        }
        else if (strcasecmp(argv[1], "IMAGE") == 0 && argc >= 3) {
            // IMAGE command format: IMAGE [iterations] filename
            int img_iterations = 1;
            char *img_filename = NULL;
            
            if (argc >= 4) {
                img_iterations = atoi(argv[2]);
                img_filename = argv[3];
            } else {
                img_filename = argv[2];
            }
            
            // Process image with iterations og disk I/O
            process_image_file_with_disk_io(img_filename, img_iterations);
            
            // Clean up and exit
            cleanup_threads();
            return 0;
        }
    }
    
    // Interactive mode
    char input[1024];
    
    while (1) {
        // Non-blocking check for user input
        fd_set readfds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms timeout
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        if (select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv) > 0) {
            if (fgets(input, sizeof(input), stdin) != NULL) {
                // Remove newline character
                size_t len = strlen(input);
                if (len > 0 && input[len-1] == '\n') {
                    input[len-1] = '\0';
                }
                
                if (strlen(input) > 0) {
                    printf("> %s\n", input);
                    
                    // STOP command
                    if (strcasecmp(input, "STOP") == 0) {
                        benchmark_running = false;
                        printf("Benchmark aborted!\n");
                    }
                    // POWER command
                    else if (strcasecmp(input, "POWER") == 0) {
                        read_power_measurements();
                    }
                    // REPEAT command
                    else if (strncasecmp(input, "REPEAT", 6) == 0) {
                        if (benchmark_running) {
                            printf("Benchmark already running. Use STOP first.\n");
                        } else {
                            // Parse command: REPEAT <count> <text>
                            char* token = input + 6; // Skip "REPEAT"
                            while (*token && isspace(*token)) token++; // Skip spaces
                            
                            // Check if there's a number
                            if (isdigit(*token)) {
                                // Parse the number
                                long iterations = atol(token);
                                
                                // Skip to the text portion
                                while (*token && isdigit(*token)) token++;
                                while (*token && isspace(*token)) token++;
                                
                                // Get the text to process
                                char* text = token;
                                
                                if (strlen(text) > 0) {
                                    printf("Starting benchmark with %ld iterations...\n", iterations);
                                    run_benchmark(text, iterations);
                                } else {
                                    printf("No text provided. Usage: REPEAT [count] [text]\n");
                                }
                            } else {
                                printf("Invalid REPEAT format. Use: REPEAT [count] [text]\n");
                            }
                        }
                    }
                    // IMAGE command
                    else if (strncasecmp(input, "IMAGE", 5) == 0) {
                        if (benchmark_running) {
                            printf("Benchmark running. Use STOP first.\n");
                        } else {
                            // Parse command: IMAGE <iterations> <filename>
                            char* token = input + 5; // Skip "IMAGE"
                            while (*token && isspace(*token)) token++; // Skip spaces
                            
                            // Get iterations (default to 1 if not specified)
                            int iterations = 1;
                            if (isdigit(*token)) {
                                iterations = atoi(token);
                                
                                // Skip to filename
                                while (*token && isdigit(*token)) token++;
                                while (*token && isspace(*token)) token++;
                            }
                            
                            // Get filename
                            char* filename = token;
                            
                            if (strlen(filename) > 0) {
                                printf("Processing image with %d iterations...\n", iterations);
                                process_image_file_with_disk_io(filename, iterations);
                            } else {
                                printf("No filename provided. Usage: IMAGE [count] [filename]\n");
                            }
                        }
                    }
                    // Direct text encryption
                    else if (!benchmark_running) {
                        // Single encryption/decryption of input text
                        unsigned char padded[MAX_SIZE] = {0};
                        unsigned char encrypted[MAX_SIZE + IV_SIZE + TAG_SIZE] = {0};
                        unsigned char decrypted[MAX_SIZE] = {0};
                        
                        // Add padding
                        size_t input_len = strlen(input);
                        size_t padded_len = padData(input, padded, input_len);
                        
                        // Encrypt data
                        struct timeval start_tv, end_tv;
                        gettimeofday(&start_tv, NULL);
                        encrypt(padded, encrypted, padded_len);
                        gettimeofday(&end_tv, NULL);
                        unsigned long encrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                                  (end_tv.tv_usec - start_tv.tv_usec);
                        
                        // Decrypt data
                        gettimeofday(&start_tv, NULL);
                        decrypt(encrypted, decrypted, padded_len + IV_SIZE + TAG_SIZE);
                        gettimeofday(&end_tv, NULL);
                        unsigned long decrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                                  (end_tv.tv_usec - start_tv.tv_usec);
                        
                        printf("\n==========================================\n");
                        printf("         SINGLE OPERATION RESULTS        \n");
                        printf("==========================================\n");
                        printf("Encrypted (with IV and tag): ");
                        printHex(encrypted, 32);
                        printf("Encryption time: %lu µs\n", encrypt_time);
                        printf("Decryption time: %lu µs\n", decrypt_time);
                        
                        // Calculate throughput
                        float enc_throughput = padded_len * 1e6 / encrypt_time;
                        float dec_throughput = padded_len * 1e6 / decrypt_time;
                        
                        printf("Encryption throughput: %.0f bytes/s\n", enc_throughput);
                        printf("Decryption throughput: %.0f bytes/s\n", dec_throughput);
                        
                        // Remove padding from decrypted data
                        size_t actual_len = removePadding(decrypted, padded_len);
                        decrypted[actual_len] = '\0';
                        
                        printf("Decrypted: %s\n", decrypted);
                        
                        // Check for expression evaluation
                        if (strstr((char*)decrypted, "(") && strstr((char*)decrypted, ")") && 
                            strstr((char*)decrypted, "=") && strstr((char*)decrypted, "?")) {
                            int result = evaluerUttrykk((char*)decrypted);
                            if (result != 0) {
                                printf("RESP:RESULT=%d\n", result);
                            }
                        }
                    } else {
                        printf("Cannot execute command while benchmark is running.\n");
                        printf("Send 'STOP' to abort benchmark\n");
                    }
                    
                    printf("\n");  // Blank line for readability
                }
            }
        }
        
        // If a benchmark is running, check for completion
        if (benchmark_running) {
            static unsigned long last_status = 0;
            unsigned long now = get_time_ms();
            
            // Show heartbeat status every 2 seconds
            if (now - last_status > 2000) {
                printf("Benchmark still running... (Press STOP to abort)\n");
                last_status = now;
            }
        }
        
        // Small delay to reduce CPU usage
        usleep(10000); // 10ms
    }
    
    // Cleanup threads (should never reach here)
    cleanup_threads();
    
    return 0;
}