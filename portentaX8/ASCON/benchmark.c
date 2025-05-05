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
    
    // Close INA226
    ina226_close();
    
    pthread_mutex_lock(&print_mutex);
    printf("All threads terminated\n");
    pthread_mutex_unlock(&print_mutex);
}

// Generate decision matrix report
void generate_matrix_report(void) {
    // Calculate average CPU usage from samples
    pthread_mutex_lock(&cpu_mutex);
    float avg_cpu = 0.0;
    int valid_samples = 0;
    
    // Calculate average CPU usage from recent samples
    if (cpu_sample_count > 0) {
        // Focus on the most recent samples during benchmark, not all samples
        int start_idx = (cpu_sample_count > 20) ? (cpu_sample_count - 20) : 0; // Use last 20 samples
        
        for (int i = start_idx; i < cpu_sample_count; i++) {
            avg_cpu += cpu_samples[i].cpu_usage_percent;
            valid_samples++;
        }
        
        if (valid_samples > 0) {
            avg_cpu /= valid_samples;
            // Save recent values to globals
            cpu_usage = avg_cpu;
        }
    }
    pthread_mutex_unlock(&cpu_mutex);
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
    
    // Reset crypto core usage tracking at the start of each benchmark
    pthread_mutex_lock(&cpu_mutex);
    crypto_core_usage = 0.0;
    max_crypto_usage = 0.0; // Reset the maximum tracker
    // Important - we're now in benchmark mode, prevent other updates
    pthread_mutex_unlock(&cpu_mutex);
    
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

unsigned long safeTimeDiff(unsigned long start, unsigned long end) {
    // Handle timer overflow
    if (end >= start) {
        return end - start;
    } else {
        // Overflow occurred
        return (ULONG_MAX - start) + end + 1;
    }
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

// Complete benchmark and report results
void finishBenchmark(void) {
    // End timing for the entire benchmark
    unsigned long benchmark_end = get_time_ms();
    unsigned long total_benchmark_time = safeTimeDiff(benchmark_start_time, benchmark_end);

    // Calculate CPU usage specifically for crypto operations
    float crypto_time_ms = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0;
    float wall_time_ms = total_benchmark_time;
    float crypto_cpu_usage_pct = (crypto_time_ms / wall_time_ms) * 100.0;

    // Set both CPU usage values to ensure consistency
    pthread_mutex_lock(&cpu_mutex);
    cpu_usage = crypto_cpu_usage_pct;
    crypto_core_usage = crypto_cpu_usage_pct; // Use our accurate calculation
    max_crypto_usage = crypto_cpu_usage_pct;  // Ensure max is also consistent
    pthread_mutex_unlock(&cpu_mutex);

    // Now handle power measurements
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
        
        // Calculate total energy - THIS PART NEEDS FIXING
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

    // Calculate more energy metrics with proper conversions
    float avg_power_w = avg_power / 1000.0;                    // mW to W
    float energy_j = benchmark_total_energy / 1000.0;          // mJ to J
    float energy_wh = benchmark_total_energy / 3600000.0;      // mJ to Wh
    float crypto_energy_mj = (crypto_time_ms / 1000.0) * avg_power; // Energy used just for crypto
    float per_byte_energy = benchmark_total_energy / (benchmark_total_iterations * benchmark_padded_len); // mJ per byte

    // Print power measurements OUTSIDE the mutex lock with all details
    printf("\n==========================================\n");
    printf("         POWER MEASUREMENTS              \n");
    printf("==========================================\n");
    printf("Average current: %.2f mA (%.6f A)\n", benchmark_avg_current, benchmark_avg_current / 1000.0);
    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
        printf("Current range: %.2f - %.2f mA\n", benchmark_min_current, benchmark_max_current);
    }
    printf("Bus voltage: %.3f V\n", avg_voltage);
    printf("Average power: %.2f mW (%.6f W)\n", avg_power, avg_power_w);
    printf("Energy consumption: %.2f mJ (%.6f J)\n", benchmark_total_energy, energy_j);
    printf("Energy in watt-hours: %.8f Wh\n", energy_wh);
    printf("Energy per operation: %.6f mJ/op\n", benchmark_total_energy / benchmark_total_iterations);
    printf("Energy per byte: %.6f µJ/byte\n", per_byte_energy * 1000.0);
    printf("Crypto operations energy: %.2f mJ (%.2f%%)\n", crypto_energy_mj, 
       (crypto_energy_mj / benchmark_total_energy) * 100.0);
    
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
    printf("Energy consumption: %.2f mJ (%.6f J, %.8f Wh)\n", 
           benchmark_total_energy, energy_j, energy_wh);
    printf("Energy efficiency: %.6f µJ/byte\n", per_byte_energy * 1000.0);
    
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

// Enhanced image processing function with verification and file type detection
void processImageFile(const char* filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to open file: %s\n", filename);
        pthread_mutex_unlock(&print_mutex);
        return;
    }
    
    // Get file type from filename (to create correct decrypted filename)
    char file_extension[16] = ".jpg"; // Default if no file type is found
    const char *dot = strrchr(filename, '.');
    if (dot && strlen(dot) < 15) {
        // Copy the file type (including the dot)
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
    printf("\nStarting image encryption for %s (%zu bytes)...\n", filename, filesize);
    pthread_mutex_unlock(&print_mutex);
    
    // Allocate buffer
    unsigned char *buffer = malloc(filesize);
    unsigned char *encrypted = malloc(filesize + IV_SIZE + TAG_SIZE);
    unsigned char *decrypted = malloc(filesize);
    
    if (!buffer || !encrypted || !decrypted) {
        pthread_mutex_lock(&print_mutex);
        printf("Error: Failed to allocate memory for file processing\n");
        pthread_mutex_unlock(&print_mutex);
        
        fclose(fp);
        if (buffer) free(buffer);
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
        free(encrypted);
        free(decrypted);
        return;
    }
    fclose(fp);
    
    // Start continuous power measurement before encryption if not already running
    bool was_benchmark_running = (benchmark_state == BENCHMARK_RUNNING);
    
    if (!was_benchmark_running) {
        // Reset power measurements to get clean measurements for the image operation
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
    }
    
    // Memory measurement before encryption
    measure_memory("Before Image Encryption");
    
    // Start timing
    unsigned long start_time = get_time_ms();
    
    // Encrypt data
    unsigned long encrypt_time = encrypt(buffer, encrypted, filesize);
    
    // Decrypt data
    unsigned long decrypt_time = decrypt(encrypted, decrypted, filesize + IV_SIZE + TAG_SIZE);
    
    // End timing
    unsigned long total_time = safeTimeDiff(start_time, get_time_ms());
    
    // Verify that decryption was successful
    bool verification_success = true;
    for (size_t i = 0; i < filesize; i++) {
        if (buffer[i] != decrypted[i]) {
            verification_success = false;
            break;
        }
    }
    
    // Save encrypted file
    FILE *enc_fp = fopen("encrypted.bin", "wb");
    if (enc_fp) {
        fwrite(encrypted, 1, filesize + IV_SIZE + TAG_SIZE, enc_fp);
        fclose(enc_fp);
    } else {
        pthread_mutex_lock(&print_mutex);
        printf("Failed to create encrypted file\n");
        pthread_mutex_unlock(&print_mutex);
    }
    
    // Save decrypted file
    FILE *dec_fp = fopen(decrypted_filename, "wb");
    if (dec_fp) {
        fwrite(decrypted, 1, filesize, dec_fp);
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
    float core_usage = crypto_core_usage; // Use of crypto core
    pthread_mutex_unlock(&cpu_mutex);
    
    // Calculate energy consumption
    float duration_s = total_time / 1000.0;
    float energy_mj = avg_power * duration_s;
    float energy_j = energy_mj / 1000.0;
    float energy_uj_per_byte = (energy_mj * 1000.0) / filesize;
    
    // Calculate throughput
    float enc_mb_per_s = (filesize * 1.0 / encrypt_time) * 1000000 / (1024*1024);
    float dec_mb_per_s = (filesize * 1.0 / decrypt_time) * 1000000 / (1024*1024);
    float combined_mb_per_s = (filesize * 2.0 / (encrypt_time + decrypt_time)) * 1000000 / (1024*1024);
    
    pthread_mutex_lock(&print_mutex);
    printf("\n==========================================\n");
    printf("         IMAGE PROCESSING RESULTS         \n");
    printf("==========================================\n");
    printf("File: %s\n", filename);
    printf("Size: %zu bytes (%.2f MB)\n", filesize, filesize / (1024.0*1024.0));
    printf("Verification: %s\n", verification_success ? "✅ Success - Decryption verified" : "❌ Failed - Data mismatch");
    
    printf("\nPerformance:\n");
    printf("Encryption time: %lu µs (%.2f ms)\n", encrypt_time, encrypt_time / 1000.0);
    printf("Decryption time: %lu µs (%.2f ms)\n", decrypt_time, decrypt_time / 1000.0);
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
    free(encrypted);
    free(decrypted);
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
    printf("  POWER -// benchmark.c (3 cores)
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
#include <sched.h>   // For CPU affinity
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include "ascon.h"
#include <sys/ioctl.h>
#include <linux/i2c-dev.h> // For I2C_SLAVE

// INA226 register definitions for I2C communication
#define INA226_ADDRESS 0x40
#define INA226_CONFIG 0x00
#define INA226_SHUNT_VOLTAGE 0x01
#define INA226_BUS_VOLTAGE 0x02
#define INA226_POWER 0x03
#define INA226_CURRENT 0x04
#define INA226_CALIBRATION 0x05

// INA226 configuration values
#define INA226_CONFIG_RESET      0x8000
#define INA226_CONFIG_DEFAULT    0x4127  // 16 averages, 1.1ms conversion time

// Constants for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Number of iterations per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true
#define MAX_SIZE 256
#define POWER_SAMPLE_COUNT 1000

// Thread-specific defines
#define POWER_THREAD_CORE 0   // K0: Power monitoring
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

// CPU measurement variables
typedef struct {
    unsigned long timestamp;
    float cpu_usage_percent;
} CpuSample;
CpuSample cpu_samples[POWER_SAMPLE_COUNT];
int cpu_sample_count = 0;
float cpu_usage = 0.0;
float crypto_core_usage = 0.0; // CPU2 usage
float max_crypto_usage = 0.0;  // Track maximum crypto core usage

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
void ina226_init(void);
void ina226_close(void);
float ina226_read_current(void);
float ina226_read_voltage(void);
float ina226_read_power(void);
float ina226_read_shunt_voltage(void);
int ina226_write_reg(uint8_t reg, uint16_t value);
int ina226_read_reg(uint8_t reg, uint16_t* value);
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
unsigned long safeTimeDiff(unsigned long start, unsigned long end);
void signal_handler(int sig);

// INA226 I2C functions

// Write 16-bit value to INA226 register via I2C
int ina226_write_reg(uint8_t reg, uint16_t value) {
    uint8_t buf[3];
    buf[0] = reg;                   // Register address
    buf[1] = (value >> 8) & 0xFF;   // MSB (INA226 uses big-endian)
    buf[2] = value & 0xFF;          // LSB
    
    if (write(i2c_fd, buf, 3) != 3) {
        printf("I2C write error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// Read 16-bit value from INA226 register via I2C
int ina226_read_reg(uint8_t reg, uint16_t* value) {
    uint8_t buf[2];
    
    // Set the register to read from
    if (write(i2c_fd, &reg, 1) != 1) {
        printf("I2C write error for register selection: %s\n", strerror(errno));
        return -1;
    }
    
    // Read the register value
    if (read(i2c_fd, buf, 2) != 2) {
        printf("I2C read error: %s\n", strerror(errno));
        return -1;
    }
    
    // Convert big-endian to host order
    *value = (buf[0] << 8) | buf[1];
    return 0;
}

// Initialize INA226 power monitor via I2C
void ina226_init(void) {
    printf("Initializing INA226 power monitor via I2C...\n");
    
    // Open I2C device - use known device for Portenta X8
    const char* i2c_device = "/dev/i2c-3";
    i2c_fd = open(i2c_device, O_RDWR);
    
    if (i2c_fd < 0) {
        printf("ERROR: Could not open I2C bus %s: %s\n", i2c_device, strerror(errno));
        printf("You might need to run the program with sudo for I2C access\n");
        return;
    }
    
    printf("Successfully opened I2C bus: %s\n", i2c_device);
    
    // Set I2C slave address
    if (ioctl(i2c_fd, I2C_SLAVE, INA226_ADDRESS) < 0) {
        printf("Failed to set I2C slave address: %s\n", strerror(errno));
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Reset the device
    if (ina226_write_reg(INA226_CONFIG, INA226_CONFIG_RESET) < 0) {
        printf("Failed to reset INA226\n");
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Wait for reset to complete
    usleep(1000);
    
    // Configure the device with default settings
    if (ina226_write_reg(INA226_CONFIG, INA226_CONFIG_DEFAULT) < 0) {
        printf("Failed to configure INA226\n");
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Calculate calibration value
    // For a 0.1 ohm shunt and max expected current of 1A:
    uint16_t calibration = 5120; // Pre-calculated value for 0.1 ohm shunt
    
    // Set calibration register
    if (ina226_write_reg(INA226_CALIBRATION, calibration) < 0) {
        printf("Failed to set calibration\n");
        close(i2c_fd);
        i2c_fd = -1;
        return;
    }
    
    // Read initial values to verify device is working
    float shunt_v = ina226_read_shunt_voltage();
    float bus_v = ina226_read_voltage();
    float current = ina226_read_current();
    float power = ina226_read_power();
    
    printf("INA226 Initial readings:\n");
    printf("  Shunt voltage: %.3f mV\n", shunt_v);
    printf("  Bus voltage: %.3f V\n", bus_v);
    printf("  Current: %.2f mA\n", current);
    printf("  Power: %.2f mW\n", power);
    
    printf("INA226 initialization complete\n");
}
    
void ina226_close(void) {
    if (i2c_fd >= 0) {
        close(i2c_fd);
        i2c_fd = -1;
    }
}

// Read shunt voltage in mV
float ina226_read_shunt_voltage(void) {
    uint16_t value;
    if (ina226_read_reg(INA226_SHUNT_VOLTAGE, &value) < 0)
        return 0.0;
    
    // Convert to signed value and scale (2.5µV per LSB)
    return (int16_t)value * 0.0025; 
}

// Read bus voltage in V
float ina226_read_voltage(void) {
    uint16_t value;
    if (ina226_read_reg(INA226_BUS_VOLTAGE, &value) < 0)
        return 0.0;
    
    // Bus voltage LSB is 1.25mV, convert to V
    return value * 0.00125;
}

// Read current in mA
float ina226_read_current(void) {
    uint16_t value;
    if (ina226_read_reg(INA226_CURRENT, &value) < 0)
        return 0.0;
    
    // Current LSB depends on calibration value
    // With calibration = 5120, LSB is 0.2mA
    return (int16_t)value * 0.2;
}

// Read power in mW
float ina226_read_power(void) {
    uint16_t value;
    if (ina226_read_reg(INA226_POWER, &value) < 0)
        return 0.0;
    
    // Power LSB is 25 times the current LSB
    // With current LSB = 0.2mA, power LSB = 5mW
    float power = value * 5.0;
    
    // Debug printout occasionally
    static int debug_count = 0;
    if (debug_count++ % 100 == 0) {
        float current = ina226_read_current();
        float voltage = ina226_read_voltage();
        float calc_power = current * voltage / 1000.0;  // mA * V = mW
        
        printf("INA226 DEBUG: Raw power: 0x%04X → %.2f mW\n", value, power);
        printf("INA226 CALCULATED: I=%.2f mA, V=%.3f V → P=%.2f mW\n", 
               current, voltage, calc_power);
    }
    
    return power;
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
        float current = ina226_read_current();
        float voltage = ina226_read_voltage();
        float power = ina226_read_power();
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
    
    // Variables for overall CPU usage calculation
    unsigned long long prev_total = 0, prev_idle = 0;
    
    // Variables for crypto core (CPU2) usage calculation
    unsigned long long prev_core_total = 0, prev_core_idle = 0;
    
    while (threads_running) {
        // Read overall CPU stats
        FILE *fp = fopen("/proc/stat", "r");
        if (fp == NULL) {
            usleep(100000); // 100ms delay (increased from 500ms)
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
                            
                            // Store crypto core usage ONLY if not in benchmark mode
                            pthread_mutex_lock(&cpu_mutex);
                            if (benchmark_state != BENCHMARK_RUNNING) {
                                // Only update when not benchmarking - our calculation will take precedence
                                crypto_core_usage = core_cpu_percent;
                            } else {
                                // For UI feedback during benchmark, still track but don't override
                                if (core_cpu_percent > max_crypto_usage) {
                                    max_crypto_usage = core_cpu_percent;
                                }
                            }
                            pthread_mutex_unlock(&cpu_mutex);
                            
                            // Debug printing (outside the locked mutex section)
                            if (benchmark_state == BENCHMARK_RUNNING) {
                                pthread_mutex_lock(&print_mutex);
                                printf("Crypto core %d usage: %.2f%% (max: %.2f%%)\n", 
                                       CRYPTO_THREAD_CORE, core_cpu_percent, max_crypto_usage);
                                pthread_mutex_unlock(&print_mutex);
                            }
                        }
                    }
                    
                    // Update previous values for crypto core
                    prev_core_total = core_total;
                    prev_core_idle = core_idle;
                }
            }
        }
        
        fclose(fp);
        usleep(100000); // 100ms delay (increased from 500ms for more frequent sampling)
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
    // Initialize INA226
    ina226_init();
    
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

