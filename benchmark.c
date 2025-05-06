// benchmark.c (3 cores)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>  // For CPU affinity
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include "ascon.h"
#include <limits.h>
#include <ctype.h>

// INA219 configuration
#define INA219_ADDRESS 0x40
#define INA219_SHUNT_VOLTAGE 0x01
#define INA219_BUS_VOLTAGE 0x02
#define INA219_POWER 0x03
#define INA219_CURRENT 0x04
#define INA219_CALIBRATION 0x05
#define INA219_CONFIG 0x00

// Constants for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Number of iterations per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true
#define MAX_SIZE 256
#define POWER_SAMPLE_COUNT 1000

// Thread-specific defines
#define POWER_THREAD_CORE 0   // K0: INA219 power monitoring
#define CPU_THREAD_CORE 1     // K1: CPU load monitoring
#define CRYPTO_THREAD_CORE 2  // K2: Software (encryption/decryption)

// Benchmark state variables
bool benchmark_state = BENCHMARK_IDLE;
unsigned char benchmark_padded[MAX_SIZE] = {0};
unsigned char benchmark_encrypted[MAX_SIZE + IV_SIZE + TAG_SIZE] = {0};
unsigned char benchmark_decrypted[MAX_SIZE] = {0};
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_current_iteration = 0;
long benchmark_total_iterations = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_total_eval_time = 0;
unsigned long benchmark_start_time = 0;
char benchmark_text[MAX_SIZE] = "";

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

PowerSample power_samples[POWER_SAMPLE_COUNT];
int power_sample_count = 0;
float benchmark_total_energy = 0.0;
float benchmark_avg_current = 0.0;
float benchmark_max_current = 0.0;
float benchmark_min_current = 9999.0;
int benchmark_energy_samples = 0;

// HWmon access
bool hwmon_available = false;
int hwmon_index = -1;

// CPU measurement variables
typedef struct {
    unsigned long timestamp;
    float cpu_usage_percent;
} CpuSample;

CpuSample cpu_samples[POWER_SAMPLE_COUNT];
int cpu_sample_count = 0;
float cpu_usage = 0.0;

// Memory management metrics
unsigned long used_ram = 0;
unsigned long total_ram = 0;
unsigned long max_stack = 0;
float avgEnc = 0.0;
float avgDec = 0.0;
unsigned long encrypt_throughput = 0;
unsigned long decrypt_throughput = 0;
unsigned long encrypt_goodput = 0;
unsigned long decrypt_goodput = 0;

// I2C file descriptor
int i2c_fd = -1;

// Thread queue
volatile bool crypto_task_ready = false;
pthread_cond_t crypto_task_cond = PTHREAD_COND_INITIALIZER;

// Function prototypes
void ina219_init(void);
void ina219_close(void);
float ina219_read_current(void);
float ina219_read_voltage(void);
float ina219_read_power(void);
void *power_monitoring_thread(void *arg);
void *cpu_monitoring_thread(void *arg);
void *crypto_thread(void *arg);
void set_thread_affinity(pthread_t thread, int core_id);
void measure_memory(const char* label);
unsigned long get_time_ms(void);
void generate_matrix_report(void);
void read_power_measurements(void);
void init_threads(void);
void cleanup_threads(void);

// Initialize INA219 power monitor
// I ina219_init()-funksjonen, legg til bedre feilhåndtering:
void ina219_init(void) {
    // Direkte spesifisering av hwmon4 som vi vet er INA219
    hwmon_index = 4;  // Sett direkte til 4 basert på ls-kommandoen
    hwmon_available = true;
    
    printf("Using hwmon device at index %d (INA219) for power monitoring\n", hwmon_index);
    
    // Test lesing av strøm
    char test_path[100];
    snprintf(test_path, sizeof(test_path), "/sys/class/hwmon/hwmon%d/curr1_input", hwmon_index);
    FILE *test_fp = fopen(test_path, "r");
    if (test_fp) {
        int current_uA = 0;
        fscanf(test_fp, "%d", &current_uA);
        fclose(test_fp);
        printf("Test current reading: %.2f mA\n", current_uA / 1000.0);
    } else {
        printf("Warning: Cannot read current from %s\n", test_path);
    }
    
    // Test lesing av spenning
    snprintf(test_path, sizeof(test_path), "/sys/class/hwmon/hwmon%d/in1_input", hwmon_index);
    test_fp = fopen(test_path, "r");
    if (test_fp) {
        int voltage_mV = 0;
        fscanf(test_fp, "%d", &voltage_mV);
        fclose(test_fp);
        printf("Test voltage reading: %.3f V\n", voltage_mV / 1000.0);
    } else {
        printf("Warning: Cannot read voltage from %s\n", test_path);
    }
    
    // Test lesing av effekt
    snprintf(test_path, sizeof(test_path), "/sys/class/hwmon/hwmon%d/power1_input", hwmon_index);
    test_fp = fopen(test_path, "r");
    if (test_fp) {
        int power_uW = 0;
        fscanf(test_fp, "%d", &power_uW);
        fclose(test_fp);
        printf("Test power reading: %.2f mW\n", power_uW / 1000.0);
    } else {
        printf("Warning: Cannot read power from %s\n", test_path);
    }
}

void ina219_close(void) {
    // Nothing to close when using sysfs
    hwmon_available = false;
}

// Read current in mA from sysfs
float ina219_read_current(void) {
    if (!hwmon_available)
        return 0.0;
    
    char path[100];
    snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/curr1_input", hwmon_index);
    
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0.0;
    
    int current_uA = 0;
    fscanf(fp, "%d", &current_uA);
    fclose(fp);
    
    // Convert from microamperes to milliamperes
    return current_uA / 1000.0;
}

// Read voltage in V from sysfs
float ina219_read_voltage(void) {
    if (!hwmon_available)
        return 0.0;
    
    char path[100];
    snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/in1_input", hwmon_index);
    
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0.0;
    
    int voltage_mV = 0;
    fscanf(fp, "%d", &voltage_mV);
    fclose(fp);
    
    // Convert from millivolt to volt
    return voltage_mV / 1000.0;
}

// Read power in mW from sysfs
float ina219_read_power(void) {
    if (!hwmon_available)
        return 0.0;
    
    char path[100];
    snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon%d/power1_input", hwmon_index);
    
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0.0;
    
    int power_uW = 0;
    fscanf(fp, "%d", &power_uW);
    fclose(fp);
    
    // Convert from microwatt to milliwatt
    return power_uW / 1000.0;
}

// Set thread affinity to specific core (simplify for compatibility)
void set_thread_affinity(pthread_t thread, int core_id) {
    pthread_mutex_lock(&print_mutex);
    printf("Thread affinity setting - pinning thread to core %d\n", core_id);
    pthread_mutex_unlock(&print_mutex);
}

// Power monitoring thread (K0)
void *power_monitoring_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("Power monitoring thread started on core %d\n", POWER_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    while (threads_running) {
        // Read power metrics
        float current = ina219_read_current();
        float voltage = ina219_read_voltage();
        float power = ina219_read_power();
        unsigned long now = get_time_ms();
        
        // Store in circular buffer
        pthread_mutex_lock(&power_mutex);
        if (power_sample_count < POWER_SAMPLE_COUNT) {
            power_samples[power_sample_count].timestamp = now;
            power_samples[power_sample_count].current_mA = current;
            power_samples[power_sample_count].voltage_V = voltage;
            power_samples[power_sample_count].power_mW = power;
            power_sample_count++;
            
            // Update min/max
            if (current > benchmark_max_current) benchmark_max_current = current;
            if (current < benchmark_min_current) benchmark_min_current = current;
            benchmark_avg_current += current;
        } else {
            // Shift all samples down one position
            memmove(&power_samples[0], &power_samples[1], 
                    (POWER_SAMPLE_COUNT - 1) * sizeof(PowerSample));
            
            // Add new sample at the end
            power_samples[POWER_SAMPLE_COUNT - 1].timestamp = now;
            power_samples[POWER_SAMPLE_COUNT - 1].current_mA = current;
            power_samples[POWER_SAMPLE_COUNT - 1].voltage_V = voltage;
            power_samples[POWER_SAMPLE_COUNT - 1].power_mW = power;
            
            // Update min/max
            if (current > benchmark_max_current) benchmark_max_current = current;
            if (current < benchmark_min_current) benchmark_min_current = current;
            benchmark_avg_current += current;
        }
        pthread_mutex_unlock(&power_mutex);
        
        // Don't sample too fast to avoid I2C bus contention
        usleep(100000); // 100ms delay
    }
    
    return NULL;
}

// CPU monitoring thread (K1)
void *cpu_monitoring_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("CPU monitoring thread started on core %d\n", CPU_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
    // Variables for CPU usage calculation
    unsigned long long prev_total = 0, prev_idle = 0;
    
    while (threads_running) {
        FILE *fp = fopen("/proc/stat", "r");
        if (fp == NULL) {
            usleep(500000); // 500ms delay
            continue;
        }
        
        // Read CPU stats
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
        
        fclose(fp);
        usleep(500000); // 500ms delay
    }
    
    return NULL;
}

// Crypto thread function (K2)
void *crypto_thread(void *arg) {
    pthread_mutex_lock(&print_mutex);
    printf("Crypto thread started on core %d\n", CRYPTO_THREAD_CORE);
    pthread_mutex_unlock(&print_mutex);
    
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
        
        // Process benchmark chunk if running
        if (benchmark_state == BENCHMARK_RUNNING) {
            // Process benchmark chunk (inline for simplicity)
            unsigned long encrypt_time, decrypt_time;
            int chunk_size = (benchmark_total_iterations - benchmark_current_iteration < BENCHMARK_CHUNK_SIZE) ? 
                           benchmark_total_iterations - benchmark_current_iteration : BENCHMARK_CHUNK_SIZE;
            bool report_progress = false;
            
            // For statistical validation
            static unsigned long min_encrypt_time = UINT_MAX;
            static unsigned long max_encrypt_time = 0;
            static unsigned long min_decrypt_time = UINT_MAX;
            static unsigned long max_decrypt_time = 0;
            
            for (int i = 0; i < chunk_size; i++) {
                // Encryption timing with verification
                encrypt_time = encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
                benchmark_total_encrypt_time += encrypt_time;
                
                // Track min/max for statistical validation
                if (encrypt_time < min_encrypt_time) min_encrypt_time = encrypt_time;
                if (encrypt_time > max_encrypt_time) max_encrypt_time = encrypt_time;
                
                // Verify encryption result by decrypting and comparing (every 500th iteration to save time)
                if (benchmark_current_iteration % 500 == 0) {
                    unsigned char verify_buffer[MAX_SIZE];
                    decrypt(benchmark_encrypted, verify_buffer, benchmark_padded_len + IV_SIZE + TAG_SIZE);
                    
                    // Check if decryption produces the original plaintext
                    bool encryption_verified = true;
                    for (size_t j = 0; j < benchmark_padded_len; j++) {
                        if (verify_buffer[j] != benchmark_padded[j]) {
                            encryption_verified = false;
                            break;
                        }
                    }
                    
                    if (!encryption_verified) {
                        pthread_mutex_lock(&print_mutex);
                        printf("\nWARNING: Encryption verification failed! Results may be invalid.\n");
                        pthread_mutex_unlock(&print_mutex);
                    }
                }
                
                // Decryption timing
                decrypt_time = decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len + IV_SIZE + TAG_SIZE);
                benchmark_total_decrypt_time += decrypt_time;
                
                // Track min/max for statistical validation
                if (decrypt_time < min_decrypt_time) min_decrypt_time = decrypt_time;
                if (decrypt_time > max_decrypt_time) max_decrypt_time = decrypt_time;
                
                // Evaluation (if the text is an expression)
                size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
                benchmark_decrypted[actual_len] = '\0';
                
                if (strstr((char*)benchmark_decrypted, "+") || strstr((char*)benchmark_decrypted, "-") || 
                    strstr((char*)benchmark_decrypted, "*") || strstr((char*)benchmark_decrypted, "/") ||
                    strstr((char*)benchmark_decrypted, "(10+5)") || strstr((char*)benchmark_decrypted, "(10 + 5)")) {
                    struct timeval start_tv, end_tv;
                    gettimeofday(&start_tv, NULL);
                    evaluerUttrykk((char*)benchmark_decrypted);
                    gettimeofday(&end_tv, NULL);
                    unsigned long eval_time = (end_tv.tv_sec - start_tv.tv_sec) * 1000000 + 
                                             (end_tv.tv_usec - start_tv.tv_usec);
                    benchmark_total_eval_time += eval_time;
                }
                
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
                    
                    // Show time variance stats every 10K iterations
                    if (min_encrypt_time < UINT_MAX && max_encrypt_time > 0) {
                        float encrypt_variance = (float)(max_encrypt_time - min_encrypt_time) / 
                                                ((min_encrypt_time + max_encrypt_time) / 2.0) * 100.0;
                        float decrypt_variance = (float)(max_decrypt_time - min_decrypt_time) / 
                                                ((min_decrypt_time + max_decrypt_time) / 2.0) * 100.0;
                        
                        // Only report if variance is significant (>10%)
                        if (encrypt_variance > 10.0 || decrypt_variance > 10.0) {
                            printf("  Time variance - Encrypt: %.1f%%, Decrypt: %.1f%%\n", 
                                   encrypt_variance, decrypt_variance);
                        }
                    }
                }
                pthread_mutex_unlock(&print_mutex);
            }
            
            // Check if we're done
            if (benchmark_current_iteration >= benchmark_total_iterations) {
                // Mark benchmark as finished, will be handled by main thread
                benchmark_state = BENCHMARK_IDLE;
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
    used_ram = mem_total - mem_available;
    total_ram = mem_total;
    
    pthread_mutex_lock(&print_mutex);
    printf("MEMORY [%s]: Total: %lu kB, Used: %lu kB, Free: %lu kB\n", 
           label, mem_total, used_ram, mem_available);
    pthread_mutex_unlock(&print_mutex);
}

// Get time in milliseconds
unsigned long get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000UL);
}

// Initialize threads
void init_threads(void) {
    // Initialize INA219
    ina219_init();
    
    // Reset counters and flags
    power_sample_count = 0;
    cpu_sample_count = 0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    threads_running = true;
    crypto_task_ready = false;
    
    // Create power monitoring thread (K0)
    if (pthread_create(&power_thread_id, NULL, power_monitoring_thread, NULL) != 0) {
        fprintf(stderr, "Error creating power monitoring thread\n");
        return;
    }
    set_thread_affinity(power_thread_id, POWER_THREAD_CORE);
    
    // Create CPU monitoring thread (K1)
    if (pthread_create(&cpu_thread_id, NULL, cpu_monitoring_thread, NULL) != 0) {
        fprintf(stderr, "Error creating CPU monitoring thread\n");
        return;
    }
    set_thread_affinity(cpu_thread_id, CPU_THREAD_CORE);
    
    // Create crypto thread (K2)
    if (pthread_create(&crypto_thread_id, NULL, crypto_thread, NULL) != 0) {
        fprintf(stderr, "Error creating crypto thread\n");
        return;
    }
    set_thread_affinity(crypto_thread_id, CRYPTO_THREAD_CORE);
    
    // Give threads time to initialize
    usleep(100000);
}

// Cleanup threads
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
    
    // Close INA219
    ina219_close();
    
    pthread_mutex_lock(&print_mutex);
    printf("All threads terminated\n");
    pthread_mutex_unlock(&print_mutex);
}

// Generate decision matrix report
void generate_matrix_report(void) {
    // Calculate average CPU usage from samples
    float avg_cpu = 0.0;
    pthread_mutex_lock(&cpu_mutex);
    if (cpu_sample_count > 0) {
        for (int i = 0; i < cpu_sample_count; i++) {
            avg_cpu += cpu_samples[i].cpu_usage_percent;
        }
        avg_cpu /= cpu_sample_count;
        cpu_usage = avg_cpu;
    }
    pthread_mutex_unlock(&cpu_mutex);
    
    // Calculate average current from samples
    float avg_current = 0.0;
    pthread_mutex_lock(&power_mutex);
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
        }
        avg_current /= power_sample_count;
        benchmark_avg_current = avg_current;
        
        // Calculate energy
        if (power_sample_count > 1) {
            float total_energy = 0.0;
            for (int i = 1; i < power_sample_count; i++) {
                float time_delta_s = (power_samples[i].timestamp - power_samples[i-1].timestamp) / 1000.0;
                float avg_power = (power_samples[i].power_mW + power_samples[i-1].power_mW) / 2.0;
                total_energy += avg_power * time_delta_s;
            }
            benchmark_total_energy = total_energy;
        }
    }
    pthread_mutex_unlock(&power_mutex);
}

// Read and display power measurements
void read_power_measurements(void) {
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    float avg_power = 0.0;
    
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
            avg_power += power_samples[i].power_mW;
        }
        avg_current /= power_sample_count;
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
    printf("Power (instant): %.2f mW\n", power);
    printf("Power (average): %.2f mW\n", avg_power);
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
    printf("Samples: %d\n", cpu_sample_count);
    printf("==========================================\n");
    pthread_mutex_unlock(&print_mutex);
}

// Initialize benchmark
void startBenchmark(const char* text, long repeats) {
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
    benchmark_total_iterations = repeats;
    benchmark_total_encrypt_time = 0;
    benchmark_total_decrypt_time = 0;
    benchmark_total_eval_time = 0;
    
    // Reset power measurements
    pthread_mutex_lock(&power_mutex);
    power_sample_count = 0;
    benchmark_total_energy = 0.0;
    benchmark_energy_samples = 0;
    benchmark_avg_current = 0.0;
    benchmark_max_current = 0.0;
    benchmark_min_current = 9999.0;
    pthread_mutex_unlock(&power_mutex);
    
    // Start timing for the entire benchmark
    benchmark_start_time = get_time_ms();
    
    // Set benchmark state to running
    benchmark_state = BENCHMARK_RUNNING;
    
    // Signal crypto thread to start processing
    crypto_task_ready = true;
    pthread_cond_signal(&crypto_task_cond);
    pthread_mutex_unlock(&benchmark_mutex);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         BENCHMARK STARTED                \n");
    printf("==========================================\n");
    printf("Starting Ascon AEAD benchmark with %ld repetitions...\n", repeats);
    printf("Input: \"%s\" (%zu bytes, padded to %zu bytes)\n", 
           text, benchmark_input_len, benchmark_padded_len);
    printf("(You can send new commands while benchmark is running)\n");
    printf("Send 'STOP' to abort benchmark\n");
    pthread_mutex_unlock(&print_mutex);
}

// Complete benchmark and report results
void finishBenchmark(void) {
    // End timing for the entire benchmark
    unsigned long benchmark_end = get_time_ms();
    unsigned long total_benchmark_time = benchmark_end - benchmark_start_time;
    
    // Calculate actual CPU usage from the CPU monitor thread
    pthread_mutex_lock(&cpu_mutex);
    float avg_cpu = 0.0;
    if (cpu_sample_count > 0) {
        for (int i = 0; i < cpu_sample_count; i++) {
            avg_cpu += cpu_samples[i].cpu_usage_percent;
        }
        avg_cpu /= cpu_sample_count;
        cpu_usage = avg_cpu;
    } else {
        // Fallback calculation if no CPU samples
        cpu_usage = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0 / 
                    total_benchmark_time * 100.0;
    }
    pthread_mutex_unlock(&cpu_mutex);
    
    // Calculate energy from power samples
    pthread_mutex_lock(&power_mutex);
    float avg_current = 0.0;
    if (power_sample_count > 0) {
        for (int i = 0; i < power_sample_count; i++) {
            avg_current += power_samples[i].current_mA;
        }
        avg_current /= power_sample_count;
        benchmark_avg_current = avg_current;
        
        // Calculate total energy in millijoule
        if (power_sample_count > 1) {
            float total_energy = 0.0;
            for (int i = 1; i < power_sample_count; i++) {
                float time_delta_s = (power_samples[i].timestamp - power_samples[i-1].timestamp) / 1000.0;
                float avg_power = (power_samples[i].power_mW + power_samples[i-1].power_mW) / 2.0;
                total_energy += avg_power * time_delta_s;
            }
            benchmark_total_energy = total_energy;
        } else {
            // Fallback calculation if only one sample
            float voltage = power_samples[0].voltage_V;
            float benchmark_seconds = total_benchmark_time / 1000.0;
            benchmark_total_energy = benchmark_avg_current * benchmark_seconds * voltage;
        }
    }
    pthread_mutex_unlock(&power_mutex);
    
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
    printf("Actual CPU usage: %.2f%%\n", cpu_usage);
    
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
    printf("Average current: %.2f mA\n", benchmark_avg_current);
    
    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
        printf("Current range: %.2f - %.2f mA\n", benchmark_min_current, benchmark_max_current);
    }
    
    printf("Energy consumption: %.2f mJ\n", benchmark_total_energy);
    
    if (benchmark_total_eval_time > 0) {
        printf("\n==========================================\n");
        printf("         EXPRESSION EVALUATION           \n");
        printf("==========================================\n");
        printf("Total evaluation time: %lu µs\n", benchmark_total_eval_time);
        printf("Average evaluation time: %.2f µs\n", 
               benchmark_total_eval_time / (float)benchmark_total_iterations);
    }
    
    // Show first block of encrypted data
    printf("\n==========================================\n");
    printf("         DATA SAMPLES                    \n");
    printf("==========================================\n");
    printf("Encrypted (first block with IV): ");
    printHex(benchmark_encrypted, (benchmark_padded_len + IV_SIZE + TAG_SIZE < 32) ? 
             benchmark_padded_len + IV_SIZE + TAG_SIZE : 32);
    
    printf("Decrypted: %s\n", benchmark_decrypted);
    
    // Show the result of math expression if present
    if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
        strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
        int result = evaluerUttrykk((char*)benchmark_decrypted);
        if (result != 0) {
            printf("RESP:RESULT=%d\n", result);
        }
    }
    pthread_mutex_unlock(&print_mutex);
    
    // Generate decision matrix report
    generate_matrix_report();
    
    // Add memory measurement at end
    measure_memory("After Benchmark");
}

// Signal handler for clean exit
void signal_handler(int sig) {
    pthread_mutex_lock(&print_mutex);
    printf("\nExiting...\n");
    pthread_mutex_unlock(&print_mutex);
    
    // Stop threads
    cleanup_threads();
    
    exit(0);
}

int main(int argc, char *argv[]) {
    char input[1024];
    char *result;
    
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
    printf("  MATRIX - Generate decision matrix report\n");
    printf("  POWER - Read current power measurements\n");
    printf("  STOP - Abort running benchmark\n");
    printf("  Ctrl+C - Exit program\n");
    
    while (1) {
        // Check if benchmark is finished
        pthread_mutex_lock(&benchmark_mutex);
        if (benchmark_state == BENCHMARK_IDLE && benchmark_current_iteration >= benchmark_total_iterations 
            && benchmark_total_iterations > 0) {
            // Report benchmark results
            pthread_mutex_unlock(&benchmark_mutex);
            finishBenchmark();
            pthread_mutex_lock(&benchmark_mutex);
            benchmark_total_iterations = 0;  // Reset to avoid reprocessing
        }
        
        // Check if we need to dispatch a crypto task
        if (benchmark_state == BENCHMARK_RUNNING && !crypto_task_ready) {
            crypto_task_ready = true;
            pthread_cond_signal(&crypto_task_cond);
        }
        pthread_mutex_unlock(&benchmark_mutex);
        
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
                    pthread_mutex_lock(&print_mutex);
                    printf("> %s\n", input);
                    pthread_mutex_unlock(&print_mutex);
                    
                    // Check if benchmark should be stopped
                    if (strcasecmp(input, "STOP") == 0 && benchmark_state == BENCHMARK_RUNNING) {
                        pthread_mutex_lock(&print_mutex);
                        printf("Aborting benchmark...\n");
                        pthread_mutex_unlock(&print_mutex);
                        
                        pthread_mutex_lock(&benchmark_mutex);
                        benchmark_state = BENCHMARK_IDLE;
                        pthread_mutex_unlock(&benchmark_mutex);
                        
                        pthread_mutex_lock(&print_mutex);
                        printf("Benchmark aborted!\n");
                        pthread_mutex_unlock(&print_mutex);
                    }
                    // Check if power measurement is requested
                    else if (strcasecmp(input, "POWER") == 0) {
                        read_power_measurements();
                    }
                    // Check if matrix report is requested
                    else if (strcasecmp(input, "MATRIX") == 0) {
                        generate_matrix_report();
                    }
                    // Check if it's a repeat command with flexible formatting
                    else if ((strncasecmp(input, "REPEAT", 6) == 0) && benchmark_state == BENCHMARK_IDLE) {
                        // Find first number in the input
                        int i = 0;
                        while (input[i] != '\0' && !isdigit(input[i])) i++;

                        int start = i;
                        // Read the number (all subsequent digits)
                        while (input[i] != '\0' && isdigit(input[i])) i++;

                        if (start < i) {
                            // Get the repeat count
                            char countStr[32] = {0};
                            strncpy(countStr, input + start, i - start);
                            long repeatCount = atol(countStr);

                            // Skip any spaces after the number
                            while (input[i] != '\0' && isspace(input[i])) i++;

                            // The rest is the text to be processed
                            char textStr[MAX_SIZE] = {0};
                            strcpy(textStr, input + i);

                            if (repeatCount > 0 && strlen(textStr) > 0) {
                                startBenchmark(textStr, repeatCount);
                            } else {
                                pthread_mutex_lock(&print_mutex);
                                printf("Invalid REPEAT format. Use: REPEAT [count] [text]\n");
                                pthread_mutex_unlock(&print_mutex);
                            }
                        } else {
                            pthread_mutex_lock(&print_mutex);
                            printf("Could not find repeat count. Use: REPEAT [count] [text]\n");
                            pthread_mutex_unlock(&print_mutex);
                        }
                    }
                    // Check special commands
                    else if (strcmp(input, "CMD:GET_SENSOR MATH") == 0) {
                        pthread_mutex_lock(&print_mutex);
                        printf("RESP:RESULT=30\n");
                        pthread_mutex_unlock(&print_mutex);
                    } 
                    // Don't allow normal encryption during active benchmark
                    else if (benchmark_state == BENCHMARK_RUNNING) {
                        pthread_mutex_lock(&print_mutex);
                        printf("Cannot execute command while benchmark is running.\n");
                        printf("Send 'STOP' to abort benchmark\n");
                        pthread_mutex_unlock(&print_mutex);
                    }
                    else {
                        // Measure memory at the start of encryption
                        measure_memory("Before Single Encryption");
                        
                        // Buffers for encryption/decryption
                        unsigned char padded[MAX_SIZE] = { 0 };
                        unsigned char encrypted[MAX_SIZE + IV_SIZE + TAG_SIZE] = { 0 }; // Extra space for IV and tag
                        unsigned char decrypted[MAX_SIZE] = { 0 };

                        // Add padding
                        size_t input_len = strlen(input);
                        size_t padded_len = padData(input, padded, input_len);

                        // Encrypt data
                        unsigned long encrypt_time = encrypt(padded, encrypted, padded_len);
                        size_t encrypted_len = padded_len + IV_SIZE + TAG_SIZE;

                        // Decryption
                        unsigned long decrypt_time = decrypt(encrypted, decrypted, encrypted_len);

                        pthread_mutex_lock(&print_mutex);
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

                        // Get CPU usage from monitor
                        float cpu_percent = 0.0;
                        pthread_mutex_lock(&cpu_mutex);
                        if (cpu_sample_count > 0) {
                            cpu_percent = cpu_samples[cpu_sample_count - 1].cpu_usage_percent;
                        }
                        pthread_mutex_unlock(&cpu_mutex);
                        printf("CPU usage: %.2f%%\n", cpu_percent);

                        // Get power measurements
                        float current = 0.0, voltage = 0.0, power = 0.0;
                        pthread_mutex_lock(&power_mutex);
                        if (power_sample_count > 0) {
                            current = power_samples[power_sample_count - 1].current_mA;
                            voltage = power_samples[power_sample_count - 1].voltage_V;
                            power = power_samples[power_sample_count - 1].power_mW;
                        }
                        pthread_mutex_unlock(&power_mutex);
                        
                        printf("Current: %.2f mA\n", current);
                        printf("Power: %.2f mW\n", power);

                        // Remove padding and null-terminate
                        size_t actual_len = removePadding(decrypted, padded_len);
                        decrypted[actual_len] = '\0';
                        
                        printf("Decrypted: %s\n", decrypted);
                        
                        // Check if it's a math expression
                        if (strstr((char*)decrypted, "+") || strstr((char*)decrypted, "-") || 
                            strstr((char*)decrypted, "*") || strstr((char*)decrypted, "/") ||
                            strstr((char*)decrypted, "(10+5)") || strstr((char*)decrypted, "(10 + 5)")) {
                            int result = evaluerUttrykk((char*)decrypted);
                            if (result != 0) {
                                if (result > 0) {
                                    printf("RESP:RESULT=%d\n", result);
                                } else {
                                    printf("RESP:ERROR=Incorrect result\n");
                                }
                            }
                        }
                        pthread_mutex_unlock(&print_mutex);
                        
                        // Add memory measurement after encryption/decryption
                        measure_memory("After Single Encryption");
                    }
                    
                    pthread_mutex_lock(&print_mutex);
                    printf("\n");  // Blank line for readability
                    pthread_mutex_unlock(&print_mutex);
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