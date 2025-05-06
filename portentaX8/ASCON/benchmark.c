#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Enable GNU extensions for CPU_SET
#endif
#define NDEBUG // Disable debug output (if applicable)
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
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h> // For I2C communication
#include <linux/i2c.h>     // For I2C structs
#include "ascon.h"

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

// Constants
#define MAX_SIZE 4096
#define POWER_SAMPLE_COUNT 1000
#define BENCHMARK_CHUNK_SIZE 100

// Thread-specific defines
#define POWER_THREAD_CORE 1
#define CPU_THREAD_CORE 2
#define CRYPTO_THREAD_CORE 0

// Benchmark state variables
bool benchmark_running = false;
unsigned char *benchmark_padded = NULL;
unsigned char *benchmark_encrypted = NULL;
unsigned char *benchmark_decrypted = NULL;
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_current_iteration = 0;
long benchmark_total_iterations = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_start_time = 0;
char *benchmark_text = NULL;

// Thread control
volatile bool threads_running = true;
pthread_t power_thread_id, cpu_thread_id, crypto_thread_id;
pthread_mutex_t power_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t benchmark_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

// Energy measurement variables
typedef struct {
    unsigned long timestamp;
    float current_mA;
    float voltage_V;
    float power_mW;
} PowerSample;
PowerSample *power_samples = NULL;
int power_sample_count = 0;
float benchmark_total_energy = 0.0;
float benchmark_avg_current = 0.0;
float benchmark_max_current = 0.0;
float benchmark_min_current = 9999.0;
int benchmark_energy_samples = 0;

// CPU measurement variables
typedef struct {
    unsigned long timestamp;
    float cpu_usage_percent;
} CpuSample;
CpuSample *cpu_samples = NULL;
int cpu_sample_count = 0;
float cpu_usage = 0.0;
float crypto_core_usage = 0.0;
float max_crypto_usage = 0.0;

// Performance metrics
float avgEnc = 0.0;
float avgDec = 0.0;
unsigned long encrypt_throughput = 0;
unsigned long decrypt_throughput = 0;
unsigned long encrypt_goodput = 0;
unsigned long decrypt_goodput = 0;

// I2C file descriptor for INA226
int i2c_fd = -1;

// Thread queue
volatile bool crypto_task_ready = false;
pthread_cond_t crypto_task_cond = PTHREAD_COND_INITIALIZER;

// Function prototypes
void init_ina226(void);
void close_ina226(void);
bool read_ina226_measurements(float *power_W, float *current_A, float *voltage_V);
void *power_monitoring_thread(void *arg);
void *cpu_monitoring_thread(void *arg);
void *crypto_thread(void *arg);
void set_thread_affinity(pthread_t thread, int core_id);
void measure_memory(const char* label);
unsigned long get_time_ms(void);
void read_power_measurements(void);
void init_threads(void);
void cleanup_threads(void);
void process_image_file(const char* filename, int iterations);
void run_benchmark(const char* text, long iterations);
void signal_handler(int sig);
bool write_ina226_register(uint8_t reg, uint16_t value);
bool read_ina226_register(uint8_t reg, uint16_t *value);
unsigned long safe_time_diff(unsigned long start, unsigned long end);

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
        fprintf(stderr, "[DEBUG] Failed to write to INA226 register 0x%02X: %s\n", reg, strerror(errno));
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
        fprintf(stderr, "[DEBUG] Failed to read from INA226 register 0x%02X: %s\n", reg, strerror(errno));
        return false;
    }

    *value = (data[0] << 8) | data[1];
    return true;
}

// Initialize INA226 power monitor
void init_ina226(void) {
    // Open I2C device (use i2c-3 for Portneta X8)
    i2c_fd = open("/dev/i2c-3", O_RDWR);
    if (i2c_fd < 0) {
        fprintf(stderr, "[DEBUG] Cannot open I2C device /dev/i2c-3: %s\n", strerror(errno));
        return;
    }

    // Configure INA226: Continuous mode, 1 sample averaging, 1.1ms conversion time
    uint16_t config = (0x4 << 13) | // Operating mode: Continuous shunt and bus
                      (0x4 << 9) |  // Shunt voltage conversion time: 1.1ms
                      (0x4 << 6) |  // Bus voltage conversion time: 1.1ms
                      (0x0 << 3) |  // Averaging: 1 sample
                      (0x7);        // Reserved
    
    if (!write_ina226_register(INA226_REG_CONFIG, config)) {
        fprintf(stderr, "[DEBUG] Failed to configure INA226\n");
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }

    // Set calibration register
    // Current_LSB = 100uA, Max current = 0.8A, Shunt = 0.1 Ohm
    // Calibration = 0.00512 / (Current_LSB * Shunt) = 0.00512 / (0.0001 * 0.1) = 512
    uint16_t calibration = 512;
    if (!write_ina226_register(INA226_REG_CALIBRATION, calibration)) {
        fprintf(stderr, "[DEBUG] Failed to set INA226 calibration\n");
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }

    fprintf(stderr, "[DEBUG] INA226 initialized successfully\n");
}

// Close INA226 connection
void close_ina226(void) {
    if (i2c_fd >= 0) {
        close(i2c_fd);
        i2c_fd = -1;
    }
}

// Read measurements from INA226
bool read_ina226_measurements(float *power_W, float *current_A, float *voltage_V) {
    if (i2c_fd < 0) {
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }

    // Read bus voltage (1.25mV per LSB)
    uint16_t bus_voltage_raw;
    if (!read_ina226_register(INA226_REG_BUS_VOLTAGE, &bus_voltage_raw)) {
        fprintf(stderr, "[DEBUG] Failed to read bus voltage\n");
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *voltage_V = bus_voltage_raw * 0.00125f; // Convert to volts
    if (*voltage_V < 0 || *voltage_V > 36) {
        fprintf(stderr, "[DEBUG] Invalid voltage reading: %f V\n", *voltage_V);
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }

    // Read current (100uA per LSB)
    uint16_t current_raw;
    if (!read_ina226_register(INA226_REG_CURRENT, &current_raw)) {
        fprintf(stderr, "[DEBUG] Failed to read current\n");
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *current_A = (int16_t)current_raw * INA226_CURRENT_LSB; // Convert to amps
    if (*current_A < -0.8f || *current_A > 0.8f) {
        fprintf(stderr, "[DEBUG] Invalid current reading: %f A\n", *current_A);
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }

    // Read power (Power_LSB = 25 * Current_LSB)
    uint16_t power_raw;
    if (!read_ina226_register(INA226_REG_POWER, &power_raw)) {
        fprintf(stderr, "[DEBUG] Failed to read power\n");
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }
    *power_W = power_raw * INA226_POWER_LSB; // Convert to watts
    if (*power_W < 0 || *power_W > 10) {
        fprintf(stderr, "[DEBUG] Invalid power reading: %f W\n", *power_W);
        *power_W = 0;
        *current_A = 0;
        *voltage_V = 0;
        return false;
    }

    return true;
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
    
    // Set affinity to designated core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(POWER_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin power thread to core %d\n", POWER_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    while (threads_running) {
        // Read power metrics from INA226
        float power_W, current_A, voltage_V;
        if (read_ina226_measurements(&power_W, &current_A, &voltage_V)) {
            unsigned long now = get_time_ms();
            
            // Store in circular buffer
            pthread_mutex_lock(&power_mutex);
            if (power_sample_count < POWER_SAMPLE_COUNT) {
                power_samples[power_sample_count].timestamp = now;
                power_samples[power_sample_count].current_mA = current_A * 1000.0f; // Convert to mA
                power_samples[power_sample_count].voltage_V = voltage_V;
                power_samples[power_sample_count].power_mW = power_W * 1000.0f;    // Convert to mW
                power_sample_count++;
                
                // Update min/max
                if (current_A * 1000.0f > benchmark_max_current) benchmark_max_current = current_A * 1000.0f;
                if (current_A * 1000.0f < benchmark_min_current && current_A > 0) benchmark_min_current = current_A * 1000.0f;
                benchmark_avg_current += current_A * 1000.0f;
                benchmark_energy_samples++;
            } else {
                // Shift all samples down one position
                memmove(&power_samples[0], &power_samples[1], 
                        (POWER_SAMPLE_COUNT - 1) * sizeof(PowerSample));
                
                // Add new sample at the end
                power_samples[POWER_SAMPLE_COUNT - 1].timestamp = now;
                power_samples[POWER_SAMPLE_COUNT - 1].current_mA = current_A * 1000.0f;
                power_samples[POWER_SAMPLE_COUNT - 1].voltage_V = voltage_V;
                power_samples[POWER_SAMPLE_COUNT - 1].power_mW = power_W * 1000.0f;
                
                // Update min/max
                if (current_A * 1000.0f > benchmark_max_current) benchmark_max_current = current_A * 1000.0f;
                if (current_A * 1000.0f < benchmark_min_current && current_A > 0) benchmark_min_current = current_A * 1000.0f;
                benchmark_avg_current += current_A * 1000.0f;
                benchmark_energy_samples++;
            }
            pthread_mutex_unlock(&power_mutex);
        }
        
        // Don't sample too fast to avoid I2C bus contention
        usleep(10000); // 10ms delay
    }
    
    return NULL;
}

// CPU monitoring thread
void *cpu_monitoring_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("CPU monitoring thread started on core %d\n", CPU_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    // Set affinity to designated core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(CPU_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin CPU thread to core %d\n", CPU_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    // Variables for overall CPU usage calculation
    unsigned long long prev_total = 0, prev_idle = 0;
    
    // Variables for crypto core usage calculation
    unsigned long long prev_core_total = 0, prev_core_idle = 0;
    
    while (threads_running) {
        // Read overall CPU stats
        FILE *fp = fopen("/proc/stat", "r");
        if (fp == NULL) {
            usleep(100000);
            continue;
        }
        
        // Read CPU stats for all cores
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), fp)) {
            unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
            sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", 
                   &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
            
            // Calculate total and idle time
            unsigned long long total_time = user + nice + system + idle + iowait + irq + softirq + steal;
            unsigned long long idle_time = idle + iowait;
            
            // Calculate CPU usage if we have previous values
            if (prev_total > 0 && prev_idle > 0) {
                unsigned long long total_delta = total_time - prev_total;
                unsigned long long idle_delta = idle_time - prev_idle;
                
                if (total_delta > 0) {
                    float cpu_percent = 100.0 * (1.0 - ((float)idle_delta / total_delta));
                    unsigned long now = get_time_ms();
                    
                    // Store in circular buffer
                    pthread_mutex_lock(&cpu_mutex);
                    if (cpu_sample_count < POWER_SAMPLE_COUNT) {
                        cpu_samples[cpu_sample_count].timestamp = now;
                        cpu_samples[cpu_sample_count].cpu_usage_percent = cpu_percent;
                        cpu_sample_count++;
                    } else {
                        // Shift all samples down one position
                        memmove(&cpu_samples[0], &cpu_samples[1], 
                                (POWER_SAMPLE_COUNT - 1) * sizeof(CpuSample));
                        
                        // Add new sample at the end
                        cpu_samples[POWER_SAMPLE_COUNT - 1].timestamp = now;
                        cpu_samples[POWER_SAMPLE_COUNT - 1].cpu_usage_percent = cpu_percent;
                    }
                    pthread_mutex_unlock(&cpu_mutex);
                }
            }
            
            // Update previous values
            prev_total = total_time;
            prev_idle = idle_time;
        }
        
        // Now read crypto core usage (CPU2) specifically
        rewind(fp);
        // Skip overall CPU line
        fgets(buffer, sizeof(buffer), fp);
        
        // Read each core until we reach the crypto core
        char core_line[256];
        for (int i = 0; i <= CRYPTO_THREAD_CORE; i++) {
            if (fgets(core_line, sizeof(core_line), fp)) {
                if (i == CRYPTO_THREAD_CORE) {
                    // Process the crypto core line
                    unsigned long long c_user, c_nice, c_system, c_idle, c_iowait, c_irq, c_softirq, c_steal;
                    int core_num;
                    sscanf(core_line, "cpu%d %llu %llu %llu %llu %llu %llu %llu %llu", 
                           &core_num, &c_user, &c_nice, &c_system, &c_idle, 
                           &c_iowait, &c_irq, &c_softirq, &c_steal);
                    
                    // Calculate total and idle time for crypto core
                    unsigned long long core_total = c_user + c_nice + c_system + c_idle + 
                                                  c_iowait + c_irq + c_softirq + c_steal;
                    unsigned long long core_idle = c_idle + c_iowait;
                    
                    // Calculate crypto core usage if we have previous values
                    if (prev_core_total > 0 && prev_core_idle > 0) {
                        unsigned long long core_total_delta = core_total - prev_core_total;
                        unsigned long long core_idle_delta = core_idle - prev_core_idle;
                        
                        if (core_total_delta > 0) {
                            float core_cpu_percent = 100.0 * (1.0 - ((float)core_idle_delta / core_total_delta));
                            
                            // Store crypto core usage
                            pthread_mutex_lock(&cpu_mutex);
                            if (!benchmark_running) {
                                // Only update when not benchmarking - our calculation will take precedence
                                crypto_core_usage = core_cpu_percent;
                            } else {
                                // For UI feedback during benchmark, still track but don't override
                                if (core_cpu_percent > max_crypto_usage) {
                                    max_crypto_usage = core_cpu_percent;
                                }
                            }
                            pthread_mutex_unlock(&cpu_mutex);
                        }
                    }
                    
                    // Update previous values for crypto core
                    prev_core_total = core_total;
                    prev_core_idle = core_idle;
                }
            }
        }
        
        fclose(fp);
        usleep(100000); // 100ms delay for less frequent sampling
    }
    
    return NULL;
}

// Crypto processing thread
void *crypto_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("Crypto thread started on core %d\n", CRYPTO_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    // Set affinity to designated core
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(CRYPTO_THREAD_CORE, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus) != 0) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to pin crypto thread to core %d\n", CRYPTO_THREAD_CORE);
        pthread_mutex_unlock(&print_mutex);
    }
    
    while (threads_running) {
        pthread_mutex_lock(&benchmark_mutex);
        
        // Wait for task if none is ready
        while (!crypto_task_ready && threads_running) {
            pthread_cond_wait(&crypto_task_cond, &benchmark_mutex);
        }
        
        // Check if we're still running
        if (!threads_running) {
            pthread_mutex_unlock(&benchmark_mutex);
            break;
        }
        
        // Process benchmark if running
        if (benchmark_running) {
            int chunk_size = (benchmark_total_iterations - benchmark_current_iteration < BENCHMARK_CHUNK_SIZE) ? 
                           benchmark_total_iterations - benchmark_current_iteration : BENCHMARK_CHUNK_SIZE;
            bool report_progress = false;
            
            for (int i = 0; i < chunk_size; i++) {
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
                
                // Show progress every 1000 repetitions
                if (benchmark_current_iteration % 1000 == 0) {
                    report_progress = true;
                }
            }
            
            // Show progress if necessary
            if (report_progress) {
                pthread_mutex_lock(&print_mutex);
                printf(".");
                fflush(stdout);
                if (benchmark_current_iteration % 10000 == 0) {
                    printf(" %ld repetitions completed\n", benchmark_current_iteration);
                }
                pthread_mutex_unlock(&print_mutex);
            }
            
            // Check if we're done
            if (benchmark_current_iteration >= benchmark_total_iterations) {
                benchmark_running = false;
            }
        }
        
        // Mark task as processed
        crypto_task_ready = false;
        pthread_mutex_unlock(&benchmark_mutex);
        
        // Small yield
        usleep(1000);
    }
    
    return NULL;
}

// Get time in milliseconds
unsigned long get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000UL);
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

// Safe time difference calculation to handle timer overflow
unsigned long safe_time_diff(unsigned long start, unsigned long end) {
    // Handle timer overflow
    if (end >= start) {
        return end - start;
    } else {
        // Overflow occurred
        return (ULONG_MAX - start) + end + 1;
    }
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
    
    // Get latest sample
    float cpu_current = 0.0;
    
    if (cpu_sample_count > 0) {
        cpu_current = cpu_samples[cpu_sample_count - 1].cpu_usage_percent;
    }
    pthread_mutex_unlock(&cpu_mutex);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         CPU MEASUREMENTS                \n");
    printf("==========================================\n");
    printf("CPU Usage (instant): %.2f%%\n", cpu_current);
    printf("CPU Usage (average): %.2f%%\n", avg_cpu);
    printf("Crypto Core Usage: %.2f%%\n", crypto_core_usage);
    printf("Samples: %d\n", cpu_sample_count);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
}

// Initialize threads and resources
void init_threads(void) {
    // Allocate memory for samples
    power_samples = (PowerSample*)malloc(POWER_SAMPLE_COUNT * sizeof(PowerSample));
    cpu_samples = (CpuSample*)malloc(POWER_SAMPLE_COUNT * sizeof(CpuSample));
    benchmark_text = (char*)malloc(MAX_SIZE);
    benchmark_padded = (unsigned char*)malloc(MAX_SIZE);
    benchmark_encrypted = (unsigned char*)malloc(MAX_SIZE + IV_SIZE + TAG_SIZE);
    benchmark_decrypted = (unsigned char*)malloc(MAX_SIZE);
    
    if (!power_samples || !cpu_samples || !benchmark_text || 
        !benchmark_padded || !benchmark_encrypted || !benchmark_decrypted) {
        fprintf(stderr, "Failed to allocate memory for buffers\n");
        exit(1);
    }
    
    // Reset counters and flags
    power_sample_count = 0;
    cpu_sample_count = 0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    threads_running = true;
    crypto_task_ready = false;
    
    // Initialize INA226
    init_ina226();
    
    // Create power monitoring thread
    if (pthread_create(&power_thread_id, NULL, power_monitoring_thread, NULL) != 0) {
        fprintf(stderr, "Error creating power monitoring thread\n");
        return;
    }
    
    // Create CPU monitoring thread
    if (pthread_create(&cpu_thread_id, NULL, cpu_monitoring_thread, NULL) != 0) {
        fprintf(stderr, "Error creating CPU monitoring thread\n");
        return;
    }
    
    // Create crypto thread
    if (pthread_create(&crypto_thread_id, NULL, crypto_thread, NULL) != 0) {
        fprintf(stderr, "Error creating crypto thread\n");
        return;
    }
    
    // Give threads time to initialize
    usleep(10000);
}

// Cleanup threads and resources
void cleanup_threads(void) {
    // Signal threads to stop
    threads_running = false;
    
    // Signal crypto thread to wake up if waiting
    pthread_mutex_lock(&benchmark_mutex);
    crypto_task_ready = true;
    pthread_cond_signal(&crypto_task_cond);
    pthread_mutex_unlock(&benchmark_mutex);
    
    // Wait for threads to finish
    pthread_join(power_thread_id, NULL);
    pthread_join(cpu_thread_id, NULL);
    pthread_join(crypto_thread_id, NULL);
    
    // Close INA226
    close_ina226();
    
    // Free memory
    free(power_samples);
    free(cpu_samples);
    free(benchmark_text);
    free(benchmark_padded);
    free(benchmark_encrypted);
    free(benchmark_decrypted);
    
    pthread_mutex_lock(&print_mutex);
    printf("All threads terminated\n");
    pthread_mutex_unlock(&print_mutex);
}

// Function to process image file with ASCON encryption
void process_image_file(const char* filename, int iterations) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to open file: %s\n", filename);
        pthread_mutex_unlock(&print_mutex);
        return;
    }
    
    // Get file extension for output filename
    char file_extension[16] = ".jpg"; // Default if no filetype found
    const char *dot = strrchr(filename, '.');
    if (dot && strlen(dot) < 15) {
        // Copy the filetype (including the dot)
        strcpy(file_extension, dot);
    }
    
    // Create filename for decrypted file
    char decrypted_filename[128] = "decrypted";
    strcat(decrypted_filename, file_extension);
    
    // Read file size
    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    pthread_mutex_lock(&print_mutex);
    printf("\nStarting image encryption for %s (%zu bytes) with %d iterations...\n", 
           filename, filesize, iterations);
    pthread_mutex_unlock(&print_mutex);
    
    // Allocate buffer
    unsigned char *buffer = malloc(filesize);
    unsigned char *padded = malloc(filesize + 16); // Add space for padding
    unsigned char *encrypted = malloc(filesize + IV_SIZE + TAG_SIZE);
    unsigned char *decrypted = malloc(filesize + 16);
    
    if (!buffer || !padded || !encrypted || !decrypted) {
        pthread_mutex_lock(&print_mutex);
        printf("Error: Failed to allocate memory for file processing\n");
        pthread_mutex_unlock(&print_mutex);
        
        fclose(fp);
        if (buffer) free(buffer);
        if (padded) free(padded);
        if (encrypted) free(encrypted);
        if (decrypted) free(decrypted);
        return;
    }
    
    // Read the file
    if (fread(buffer, 1, filesize, fp) != filesize) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to read entire file\n");
        pthread_mutex_unlock(&print_mutex);
        
        fclose(fp);
        free(buffer);
        free(padded);
        free(encrypted);
        free(decrypted);
        return;
    }
    fclose(fp);
    
    // Reset power measurements for clean measurements
    pthread_mutex_lock(&power_mutex);
    power_sample_count = 0;
    benchmark_total_energy = 0.0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    pthread_mutex_unlock(&power_mutex);
    
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = 0.0;
    max_crypto_usage = 0.0;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Perform padding once
    size_t padded_len = padData((char*)buffer, padded, filesize);
    
    // Memory measurement before encryption
    measure_memory("Before Image Encryption");
    
    // Start timing
    unsigned long start_time = get_time_ms();
    unsigned long total_encrypt_time = 0;
    unsigned long total_decrypt_time = 0;
    
    // Set benchmark state to running
    benchmark_running = true;
    
    // Perform encryption/decryption iterations times
    for (int i = 0; i < iterations; i++) {
        // Encrypt data
        struct timeval start_tv, end_tv;
        gettimeofday(&start_tv, NULL);
        encrypt(padded, encrypted, padded_len);
        gettimeofday(&end_tv, NULL);
        unsigned long encrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        total_encrypt_time += encrypt_time;
        
        // Decrypt data
        gettimeofday(&start_tv, NULL);
        decrypt(encrypted, decrypted, padded_len + IV_SIZE + TAG_SIZE);
        gettimeofday(&end_tv, NULL);
        unsigned long decrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                   (end_tv.tv_usec - start_tv.tv_usec);
        total_decrypt_time += decrypt_time;
        
        // Show progress every 100 iterations
        if (i > 0 && i % 100 == 0) {
            pthread_mutex_lock(&print_mutex);
            printf(".");
            fflush(stdout);
            if (i % 500 == 0) {
                printf(" %d iterations completed\n", i);
            }
            pthread_mutex_unlock(&print_mutex);
        }
    }
    
    // End timing
    unsigned long total_time = safe_time_diff(start_time, get_time_ms());
    
    // Verify that decryption was successful
    size_t actual_len = removePadding(decrypted, padded_len);
    bool verification_success = true;
    if (actual_len != filesize) {
        verification_success = false;
    } else {
        for (size_t i = 0; i < filesize; i++) {
            if (buffer[i] != decrypted[i]) {
                verification_success = false;
                break;
            }
        }
    }
    
    // End benchmark state
    benchmark_running = false;
    
    // Save encrypted file
    FILE *enc_fp = fopen("encrypted.bin", "wb");
    if (enc_fp) {
        fwrite(encrypted, 1, padded_len + IV_SIZE + TAG_SIZE, enc_fp);
        fclose(enc_fp);
    } else {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to create encrypted file\n");
        pthread_mutex_unlock(&print_mutex);
    }
    
    // Save decrypted file
    FILE *dec_fp = fopen(decrypted_filename, "wb");
    if (dec_fp) {
        fwrite(decrypted, 1, actual_len, dec_fp);
        fclose(dec_fp);
    } else {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to create decrypted file\n");
        pthread_mutex_unlock(&print_mutex);
    }
    
    // Memory measurement after encryption
    measure_memory("After Image Processing");
    
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
    float cpu_percent = 0.0;
    if (cpu_sample_count > 0) {
        // Use the last 20 samples for best accuracy
        int start_idx = (cpu_sample_count > 20) ? (cpu_sample_count - 20) : 0;
        int valid_samples = 0;
        
        for (int i = start_idx; i < cpu_sample_count; i++) {
            cpu_percent += cpu_samples[i].cpu_usage_percent;
            valid_samples++;
        }
        
        if (valid_samples > 0) {
            cpu_percent /= valid_samples;
        }
    }
    float core_usage = crypto_core_usage;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Calculate energy consumption
    float duration_s = total_time / 1000.0;
    float energy_mj = avg_power * duration_s;
    float energy_j = energy_mj / 1000.0;
    float energy_uj_per_byte = (energy_mj * 1000.0) / (filesize * iterations);
    
    // Calculate throughput
    float avg_enc_time = total_encrypt_time / (float)iterations;
    float avg_dec_time = total_decrypt_time / (float)iterations;
    float enc_mb_per_s = (filesize * 1.0 / avg_enc_time) * 1000000 / (1024*1024);
    float dec_mb_per_s = (filesize * 1.0 / avg_dec_time) * 1000000 / (1024*1024);
    float combined_mb_per_s = (filesize * 2.0 / (avg_enc_time + avg_dec_time)) * 1000000 / (1024*1024);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         IMAGE PROCESSING RESULTS         \n");
    printf("==========================================\n");
    printf("File: %s\n", filename);
    printf("Size: %zu bytes (%.2f MB)\n", filesize, filesize / (1024.0*1024.0));
    printf("Iterations: %d\n", iterations);
    printf("Total data processed: %zu bytes (%.2f MB)\n", 
           filesize * iterations, (filesize * iterations) / (1024.0 * 1024.0));
    printf("Verification: %s\n", verification_success ? "✅ Success - Decryption verified" : "❌ Failed - Data mismatch");
    
    printf("\nPerformance:\n");
    printf("Average encryption time: %.2f µs (%.2f ms)\n", avg_enc_time, avg_enc_time / 1000.0);
    printf("Average decryption time: %.2f µs (%.2f ms)\n", avg_dec_time, avg_dec_time / 1000.0);
    printf("Total processing time: %lu ms\n", total_time);
    printf("Throughput (encryption): %.2f MB/s\n", enc_mb_per_s);
    printf("Throughput (decryption): %.2f MB/s\n", dec_mb_per_s);
    printf("Throughput (combined): %.2f MB/s\n", combined_mb_per_s);
    
    printf("\nPower metrics:\n");
    printf("Current: %.2f mA\n", avg_current);
    printf("Voltage: %.3f V\n", avg_voltage);
    printf("Power: %.2f mW (%.6f W)\n", avg_power, avg_power / 1000.0);
    printf("Energy consumption: %.2f mJ (%.6f J)\n", energy_mj, energy_j);
    printf("Energy per byte: %.2f µJ/byte\n", energy_uj_per_byte);
    printf("CPU usage: %.2f%% (crypto core: %.2f%%)\n", cpu_percent, core_usage);
    
    printf("\nOutput files:\n");
    printf("Encrypted file saved as: encrypted.bin\n");
    printf("Decrypted file saved as: %s\n", decrypted_filename);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
    
    free(buffer);
    free(padded);
    free(encrypted);
    free(decrypted);
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
    
    // Initialize benchmark variables
    pthread_mutex_lock(&benchmark_mutex);
    benchmark_current_iteration = 0;
    benchmark_total_iterations = iterations;
    benchmark_total_encrypt_time = 0;
    benchmark_total_decrypt_time = 0;
    
    // Reset crypto core usage tracking
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = 0.0;
    max_crypto_usage = 0.0;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Reset power measurements
    pthread_mutex_lock(&power_mutex);
    power_sample_count = 0;
    benchmark_total_energy = 0.0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    pthread_mutex_unlock(&power_mutex);
    
    // Start timing for the entire benchmark
    benchmark_start_time = get_time_ms();
    
    // Set benchmark state to running
    benchmark_running = true;
    
    // Signal crypto thread to start
    crypto_task_ready = true;
    pthread_cond_signal(&crypto_task_cond);
    pthread_mutex_unlock(&benchmark_mutex);
    
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
    
    // Wait for benchmark to complete
    while (benchmark_running) {
        // Check if benchmark is done
        pthread_mutex_lock(&benchmark_mutex);
        if (benchmark_current_iteration >= benchmark_total_iterations) {
            benchmark_running = false;
        }
        pthread_mutex_unlock(&benchmark_mutex);
        usleep(10000); // 10ms sleep to avoid busy waiting
    }
    
    // End timing for the entire benchmark
    unsigned long benchmark_end = get_time_ms();
    unsigned long total_benchmark_time = safe_time_diff(benchmark_start_time, benchmark_end);
    
    // Calculate CPU usage specifically for crypto operations
    float crypto_time_ms = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0;
    float wall_time_ms = total_benchmark_time;
    float crypto_cpu_usage_pct = (crypto_time_ms / wall_time_ms) * 100.0;
    
    // Set CPU usage values
    pthread_mutex_lock(&cpu_mutex);
    cpu_usage = crypto_cpu_usage_pct;
    crypto_core_usage = crypto_cpu_usage_pct;
    max_crypto_usage = crypto_cpu_usage_pct;
    pthread_mutex_unlock(&cpu_mutex);
    
    // Handle power measurements
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    float avg_voltage = 0.0;
    float avg_power = 0.0;
    
    if (power_sample_count > 0) {
        // Calculate averages
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
            avg_voltage += power_samples[i].voltage_V;
            avg_power += power_samples[i].power_mW;
        }
        avg_current /= power_sample_count;
        avg_voltage /= power_sample_count;
        avg_power /= power_sample_count;
        benchmark_avg_current = avg_current;
        
        // Calculate total energy
        if (power_sample_count > 1) {
            float total_energy = 0.0;
            for (int i = 1; i < power_sample_count; i++) {
                float time_delta_s = (power_samples[i].timestamp - power_samples[i-1].timestamp) / 1000.0;
                float block_avg_power = (power_samples[i].power_mW + power_samples[i-1].power_mW) / 2.0;
                total_energy += block_avg_power * time_delta_s;
            }
            benchmark_total_energy = total_energy;
        } else if (power_sample_count == 1) {
            // Fallback for single sample
            float duration_s = (get_time_ms() - benchmark_start_time) / 1000.0;
            benchmark_total_energy = avg_power * duration_s;
        }
    }
    pthread_mutex_unlock(&power_mutex);
    
    // Calculate energy metrics with proper conversions
    float avg_power_w = avg_power / 1000.0;                    // mW to W
    float energy_j = benchmark_total_energy / 1000.0;          // mJ to J
    float energy_wh = benchmark_total_energy / 3600000.0;      // mJ to Wh
    float crypto_energy_mj = (crypto_time_ms / 1000.0) * avg_power; // Energy used just for crypto
    float per_byte_energy = benchmark_total_energy / (benchmark_total_iterations * benchmark_padded_len); // mJ per byte
    
    // Calculate total combined time and average
    unsigned long total_combined_time = benchmark_total_encrypt_time + benchmark_total_decrypt_time;
    float combined_average_time = total_combined_time / (float)(benchmark_total_iterations * 2);
    
    // Calculate per-byte latency
    avgEnc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
    avgDec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;
    
    // Calculate throughput (bytes per second)
    encrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgEnc);
    decrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgDec);
    
    // Calculate goodput (effective bytes per second, excluding overhead)
    encrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgEnc);
    decrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgDec);
    
    // Calculate overhead percentage
    float protocol_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
    
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
    printf("Crypto core usage: %.2f%%\n", crypto_core_usage);
    
    printf("\nAverage time per operation:\n");
    printf("  Encryption: %.2f µs\n", avgEnc);
    printf("  Decryption: %.2f µs\n", avgDec);
    printf("  Combined average: %.2f µs\n", combined_average_time);
    
    // Performance metrics from combined benchmark
    printf("\nPerformance metrics:\n");
    printf("Encryption throughput: %lu bytes/s\n", encrypt_throughput);
    printf("Decryption throughput: %lu bytes/s\n", decrypt_throughput);
    printf("Encryption goodput: %lu bytes/s\n", encrypt_goodput);
    printf("Decryption goodput: %lu bytes/s\n", decrypt_goodput);
    
    // Protocol overhead breakdown
    printf("Protocol overhead: %.1f%%\n", protocol_overhead_pct);
    
    printf("\n==========================================\n");
    printf("         POWER MEASUREMENTS              \n");
    printf("==========================================\n");
    printf("Average current: %.2f mA (%.6f A)\n", benchmark_avg_current, benchmark_avg_current / 1000.0);
    
    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
        printf("Current range: %.2f - %.2f mA\n", benchmark_min_current, benchmark_max_current);
    }
    
    printf("Bus voltage: %.3f V\n", avg_voltage);
    printf("Average power: %.2f mW (%.6f W)\n", avg_power, avg_power_w);
    printf("Energy consumption: %.2f mJ (%.6f J, %.8f Wh)\n", 
           benchmark_total_energy, energy_j, energy_wh);
    printf("Energy per operation: %.6f mJ/op\n", benchmark_total_energy / benchmark_total_iterations);
    printf("Energy per byte: %.6f µJ/byte\n", per_byte_energy * 1000.0);
    printf("Crypto operations energy: %.2f mJ (%.2f%%)\n", crypto_energy_mj, 
           (crypto_energy_mj / benchmark_total_energy) * 100.0);
    
    // Show first block of encrypted data
    printf("\n==========================================\n");
    printf("         DATA SAMPLES                    \n");
    printf("==========================================\n");
    printf("Encrypted (first block with IV): ");
    printHex(benchmark_encrypted, (benchmark_padded_len + IV_SIZE + TAG_SIZE < 32) ? 
             benchmark_padded_len + IV_SIZE + TAG_SIZE : 32);
    
    // Remove padding from decrypted data for display
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    printf("Decrypted: %s\n", benchmark_decrypted);
    
    // Special handling for math expressions
    if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
        strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
        int result = evaluerUttrykk((char*)benchmark_decrypted);
        if (result != 0) {
            printf("Expression result: %d\n", result);
            printf("RESP:RESULT=%d\n", result);
        }
    }
    
    pthread_mutex_unlock(&print_mutex);
    
    // Add memory measurement at end
    measure_memory("After Benchmark");
}

// Signal handler for clean termination
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nReceived Ctrl+C, cleaning up and exiting...\n");
        threads_running = false;
        
        // Wait a moment for threads to notice the flag
        usleep(200000);
        
        // Force cleanup
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
    printf("  IMAGE [count] [filename] - Process image\n");
    printf("  POWER - Read current power measurements\n");
    printf("  STOP - Abort running benchmark\n");
    printf("  Ctrl+C - Exit program\n");
    
    // Parse command line arguments if provided
    if (argc >= 2) {
        if (strcasecmp(argv[1], "REPEAT") == 0 && argc >= 4) {
            // REPEAT command format: REPEAT iterations text
            long iterations = 0;
            iterations = atol(argv[2]);
            
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
            
            // Process image with iterations
            process_image_file(img_filename, img_iterations);
            
            // Clean up and exit
            cleanup_threads();
            return 0;
        }
    }
    
    // Interactive mode
    char input[1024];
    char *result;
    
    while (1) {
        // Check if benchmark should be stopped
        if (benchmark_running) {
            pthread_mutex_lock(&benchmark_mutex);
            if (benchmark_current_iteration >= benchmark_total_iterations) {
                benchmark_running = false;
            }
            pthread_mutex_unlock(&benchmark_mutex);
        }
        
        // Check for user input (non-blocking)
        fd_set readfds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms timeout
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        if (select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv) > 0) {
            result = fgets(input, sizeof(input), stdin);
            
            if (result != NULL) {
                // Remove newline character
                size_t len = strlen(input);
                if (len > 0 && input[len-1] == '\n') {
                    input[len-1] = '\0';
                }
                
                if (strlen(input) > 0) {
                    printf("> %s\n", input);
                    
                    // Stop running benchmark if requested
                    if (strcasecmp(input, "STOP") == 0 && benchmark_running) {
                        pthread_mutex_lock(&print_mutex);
                        printf("Aborting benchmark...\n");
                        pthread_mutex_unlock(&print_mutex);
                        
                        benchmark_running = false;
                        
                        pthread_mutex_lock(&print_mutex);
                        printf("Benchmark aborted!\n");
                        pthread_mutex_unlock(&print_mutex);
                    }
                    // Check for POWER command
                    else if (strcasecmp(input, "POWER") == 0) {
                        read_power_measurements();
                    }
                    // Check for IMAGE command
                    else if (strncasecmp(input, "IMAGE", 5) == 0 && !benchmark_running) {
                        // Parse command: IMAGE <iterations> <filename>
                        char* token = input + 5;
                        while (*token && isspace(*token)) token++; // Skip spaces
                        
                        // Get iterations
                        int iterations = 1;
                        if (isdigit(*token)) {
                            iterations = atoi(token);
                            // Skip to next token
                            while (*token && !isspace(*token)) token++;
                            while (*token && isspace(*token)) token++;
                        }
                        
                        // Get filename
                        char* filename = token;
                        
                        // Process image if filename is valid
                        if (strlen(filename) > 0) {
                            process_image_file(filename, iterations);
                        } else {
                            printf("Usage: IMAGE <iterations> <filename>\n");
                        }
                    }
                    // Check for REPEAT command
                    else if (strncasecmp(input, "REPEAT", 6) == 0 && !benchmark_running) {
                        // Parse command: REPEAT <count> <text>
                        char* token = input + 6;
                        while (*token && isspace(*token)) token++; // Skip spaces
                        
                        // Get iterations
                        if (isdigit(*token)) {
                            long iterations = atol(token);
                            // Skip to next token
                            while (*token && !isspace(*token)) token++;
                            while (*token && isspace(*token)) token++;
                            
                            // Get text
                            char* text = token;
                            
                            // Run benchmark if text is valid
                            if (strlen(text) > 0) {
                                run_benchmark(text, iterations);
                            } else {
                                printf("Usage: REPEAT <count> <text>\n");
                            }
                        } else {
                            printf("Invalid REPEAT format. Use: REPEAT [count] [text]\n");
                        }
                    }
                    // Regular text input for direct encryption
                    else if (!benchmark_running) {
                        // Single encryption/decryption
                        unsigned char padded[MAX_SIZE] = { 0 };
                        unsigned char encrypted[MAX_SIZE + IV_SIZE + TAG_SIZE] = { 0 };
                        unsigned char decrypted[MAX_SIZE] = { 0 };
                        
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
                        size_t encrypted_len = padded_len + IV_SIZE + TAG_SIZE;
                        
                        // Decryption
                        gettimeofday(&start_tv, NULL);
                        decrypt(encrypted, decrypted, encrypted_len);
                        gettimeofday(&end_tv, NULL);
                        unsigned long decrypt_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                                  (end_tv.tv_usec - start_tv.tv_usec);
                        
                        printf("\n==========================================\n");
                        printf("         SINGLE OPERATION RESULTS        \n");
                        printf("==========================================\n");
                        printf("Encrypted (with IV and tag): ");
                        printHex(encrypted, (encrypted_len < 32) ? encrypted_len : 32);
                        printf("Encryption time: %lu µs\n", encrypt_time);
                        printf("Decryption time: %lu µs\n", decrypt_time);
                        
                        // Calculate throughput and goodput
                        float encrypt_throughput = padded_len * 1e6 / encrypt_time;
                        float decrypt_throughput = padded_len * 1e6 / decrypt_time;
                        float encrypt_goodput = input_len * 1e6 / encrypt_time;
                        float decrypt_goodput = input_len * 1e6 / decrypt_time;
                        
                        printf("Encryption throughput: %.0f bytes/s\n", encrypt_throughput);
                        printf("Decryption throughput: %.0f bytes/s\n", decrypt_throughput);
                        printf("Encryption goodput: %.0f bytes/s\n", encrypt_goodput);
                        printf("Decryption goodput: %.0f bytes/s\n", decrypt_goodput);
                        
                        // Show power measurements
                        pthread_mutex_lock(&power_mutex);
                        float current = 0.0, voltage = 0.0, power = 0.0;
                        if (power_sample_count > 0) {
                            current = power_samples[power_sample_count - 1].current_mA;
                            voltage = power_samples[power_sample_count - 1].voltage_V;
                            power = power_samples[power_sample_count - 1].power_mW;
                        }
                        pthread_mutex_unlock(&power_mutex);
                        
                        printf("Current: %.2f mA\n", current);
                        printf("Power: %.2f mW (%.3f W)\n", power, power / 1000.0);
                        
                        // Remove padding and null-terminate
                        size_t actual_len = removePadding(decrypted, padded_len);
                        decrypted[actual_len] = '\0';
                        
                        printf("Decrypted: %s\n", decrypted);
                        
                        // Check if it's a math expression
                        if (strstr((char*)decrypted, "(") && strstr((char*)decrypted, "=") && 
                            strstr((char*)decrypted, "?")) {
                            int result = evaluerUttrykk((char*)decrypted);
                            if (result != 0) {
                                printf("Expression result: %d\n", result);
                                printf("RESP:RESULT=%d\n", result);
                            }
                        }
                    } else {
                        pthread_mutex_lock(&print_mutex);
                        printf("Cannot execute command while benchmark is running.\n");
                        printf("Send 'STOP' to abort benchmark\n");
                        pthread_mutex_unlock(&print_mutex);
                    }
                    
                    printf("\n");  // Blank line for readability
                }
            }
        }
        
        // Small delay to reduce CPU usage
        usleep(10000); // 10ms
    }
    
    // Cleanup threads (should never reach here)
    cleanup_threads();
    
    return 0;
}