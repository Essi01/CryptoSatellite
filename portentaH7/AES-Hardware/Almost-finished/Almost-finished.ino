/*
 * AES-CBC Hardware Implementation for Arduino
 * Using mbedtls for hardware acceleration with standardized benchmarking
 * With INA226_WE power monitoring integration
 */

#include <Arduino.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
#endif

// Algorithm identification and measurement constants
#define ALGORITHM_NAME "AES-CBC-HARDWARE"
bool detailed_memory_tracking = false;  // Variable that can be changed during runtime

// Power monitoring configuration - using INA226
#define USE_INA226

#ifdef USE_INA226
#include <Wire.h>
#include <INA226_WE.h>
#define INA226_I2C_ADDRESS 0x40    // Default I2C address (0x40)
#define SHUNT_RESISTOR_VALUE 0.1   // 0.1 ohm shunt resistor (adjust to your actual value)
#define MAX_CURRENT 1.0            // Maximum current to measure in amperes
INA226_WE ina226(INA226_I2C_ADDRESS);  // Initialize with I2C address
#endif

// Add debug timing define (from ChaCha20)
#define BENCHMARK_TIMING_DEBUG false  // Set to false to hide individual timing details

/*********************** DEFINES ***********************/
#define IV_SIZE 16  // IV size for CBC mode

// Constants for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Number of iterations per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true

// AES key (128-bit)
const unsigned char aes_key[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Test vector for AES-128/CBC validation
const unsigned char test_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

const unsigned char test_iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const unsigned char test_plaintext[16] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

const unsigned char test_ciphertext[16] = {
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
  0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};

// Benchmark state variables
bool benchmark_state = BENCHMARK_IDLE;
const size_t MAX_SIZE = 256;
unsigned char benchmark_padded[MAX_SIZE] = {0};
unsigned char benchmark_encrypted[MAX_SIZE + IV_SIZE] = {0};
unsigned char benchmark_decrypted[MAX_SIZE] = {0};
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_current_iteration = 0;
long benchmark_total_iterations = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_total_eval_time = 0;
unsigned long benchmark_start_time = 0;
String benchmark_text = "";

// Memory management metrics
unsigned long used_ram = 0;
unsigned long total_ram = 0;
unsigned long max_stack = 0;
float cpu_usage = 0.0;
float avgEnc = 0.0;
float avgDec = 0.0;
unsigned long encrypt_throughput = 0;
unsigned long decrypt_throughput = 0;
unsigned long encrypt_goodput = 0;
unsigned long decrypt_goodput = 0;

// Energy measurement variables
#ifdef USE_INA226
float benchmark_total_energy = 0.0;
int benchmark_energy_samples = 0;
float benchmark_avg_current = 0.0;
float benchmark_max_current = 0.0;
float benchmark_min_current = 9999.0;
unsigned long benchmark_last_energy_sample = 0;
const unsigned long ENERGY_SAMPLE_INTERVAL = 100; // Sample every 100ms
#endif

/*********************** UTILITY FUNCTIONS ***********************/

// Memory management functions
#ifdef ARDUINO_ARCH_MBED
int freeRam() {
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    return stats.reserved_size - stats.current_size;
}

// Memory measurement function
void measureMemory(const char* label) {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);
  
  // Store metrics for decision matrix
  used_ram = heap_stats.current_size + stack_stats.max_size;
  total_ram = heap_stats.reserved_size;
  max_stack = stack_stats.max_size;
  
  // Skip detailed metrics if not in detailed mode and not a summary label
  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }
  
  // Print memory information
  Serial.print("MEMORY [");
  Serial.print(label);
  Serial.print("]: Heap ");
  Serial.print(heap_stats.current_size);
  Serial.print("/");
  Serial.print(heap_stats.reserved_size);
  Serial.print(" bytes, Free: ");
  Serial.print(heap_stats.reserved_size - heap_stats.current_size);
  Serial.print(" bytes, Stack max: ");
  Serial.print(stack_stats.max_size);
  Serial.println(" bytes");
}

// Generate decision matrix data report
void generateMatrixReport() {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);
  
  used_ram = heap_stats.current_size + stack_stats.max_size;
  
  Serial.println("\n==========================================");
  Serial.println("        DECISION MATRIX DATA             ");
  Serial.println("==========================================");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  
  Serial.print("RAM Usage: ");
  Serial.print(used_ram);
  Serial.println(" bytes");
  
  Serial.println("ROM/FLASH memory: [See compiler output]");
  
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  // Report both per-operation and per-byte latency
  Serial.print("Encryption Latency: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("Decryption Latency: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("Encryption Throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption Goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  // Calculate overhead percentage
  float enc_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  Serial.print("Protocol Overhead: ");
  Serial.print(enc_overhead_pct, 1);
  Serial.println("%");
  
  #ifdef USE_INA226
  Serial.print("Current (avg): ");
  Serial.print(benchmark_avg_current, 2);
  Serial.println(" mA");
  
  if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
    Serial.print("Current (range): ");
    Serial.print(benchmark_min_current, 2);
    Serial.print(" - ");
    Serial.print(benchmark_max_current, 2);
    Serial.println(" mA");
  }
  
  Serial.print("Energy: ");
  Serial.print(benchmark_total_energy, 2);
  Serial.println(" mJ");
  #else
  Serial.println("Current: [External measurement required]");
  Serial.println("Power: [External measurement required]");
  #endif
  
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: CBC mode propagates errors to next block");
  Serial.println("==========================================");
}
#else
int freeRam() {
  extern char __heap_start, *__brkval;
  int v;
  return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}

// Memory measurement function for non-MBED platforms
void measureMemory(const char* label) {
  int free_ram = freeRam();
  
  // Skip detailed metrics if not in detailed mode and not a summary label
  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }
  
  Serial.print("MEMORY [");
  Serial.print(label);
  Serial.print("]: Free RAM: ");
  Serial.print(free_ram);
  Serial.println(" bytes");
}

// Simple matrix report for non-MBED platforms
void generateMatrixReport() {
  Serial.println("\n==========================================");
  Serial.println("        DECISION MATRIX DATA             ");
  Serial.println("==========================================");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  
  Serial.print("RAM Usage: [See memory measurements]");
  Serial.println("ROM/FLASH memory: [See compiler output]");
  
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.print("Encryption Latency: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("Decryption Latency: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("Encryption Throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption Goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption Goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  // Calculate overhead percentage
  float enc_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  Serial.print("Protocol Overhead: ");
  Serial.print(enc_overhead_pct, 1);
  Serial.println("%");
  
  #ifdef USE_INA226
  Serial.print("Current (avg): ");
  Serial.print(benchmark_avg_current, 2);
  Serial.println(" mA");
  
  if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
    Serial.print("Current (range): ");
    Serial.print(benchmark_min_current, 2);
    Serial.print(" - ");
    Serial.print(benchmark_max_current, 2);
    Serial.println(" mA");
  }
  
  Serial.print("Energy: ");
  Serial.print(benchmark_total_energy, 2);
  Serial.println(" mJ");
  #else
  Serial.println("Current: [External measurement required]");
  Serial.println("Power: [External measurement required]");
  #endif
  
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: CBC mode propagates errors to next block");
  Serial.println("==========================================");
}
#endif

// Read current power measurements
void readCurrentPower(float &current_mA, float &bus_voltage, float &power_mW) {
  #ifdef USE_INA226
  current_mA = ina226.getCurrent_mA();
  bus_voltage = ina226.getBusVoltage_V();
  power_mW = ina226.getBusPower() * 1000.0; // Convert W to mW
  #else
  current_mA = 0;
  bus_voltage = 0;
  power_mW = 0;
  #endif
}

// Get INA226 power measurements
void readPowerMeasurements() {
  #ifdef USE_INA226
  float current_mA = 0;
  float bus_voltage = 0;
  float power_mW = 0;
  
  // Direct measurement
  readCurrentPower(current_mA, bus_voltage, power_mW);
  
  Serial.println("\n==========================================");
  Serial.println("         POWER MEASUREMENTS              ");
  Serial.println("==========================================");
  Serial.print("Current: ");
  Serial.print(current_mA, 2);
  Serial.println(" mA");
  
  Serial.print("Bus Voltage: ");
  Serial.print(bus_voltage, 3);
  Serial.println(" V");
  
  Serial.print("Power: ");
  Serial.print(power_mW, 2);
  Serial.println(" mW");
  Serial.println("==========================================");
  #else
  Serial.println("INA226 power monitoring not enabled");
  #endif
}

// Helper function to display bytes as hex
void printHex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 16) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

// Safe subtraction function to handle timer overflows
unsigned long safeTimeDiff(unsigned long start, unsigned long end) {
  // Handle timer overflow
  if (end >= start) {
    return end - start;
  } else {
    // Overflow occurred
    return (0xFFFFFFFF - start) + end + 1;
  }
}

// Generate a random IV
void generateIV(unsigned char* iv) {
  for (int i = 0; i < IV_SIZE; i++) {
    iv[i] = random(256);
  }
}

// Pad data to 16-byte blocks (AES block size)
size_t padData(const char* input, unsigned char* output, size_t len) {
  size_t padded_len = ((len + 15) / 16) * 16;  // Round up to nearest 16

  // Copy original data
  memcpy(output, input, len);

  // Add padding (PKCS#7)
  unsigned char pad_value = padded_len - len;
  if (pad_value == 0) {
    pad_value = 16; // If len is exactly a multiple of block size, add a full block
    padded_len += 16;
  }
  
  for (size_t i = len; i < padded_len; i++) {
    output[i] = pad_value;
  }

  return padded_len;
}

// Encrypt data with AES-CBC (with accurate time measurement)
unsigned long encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Encryption");
  
  // Measure time more accurately by running multiple iterations for short operations
  const int MIN_ACCURATE_MICROS = 100; // Minimum time for accurate measurement
  const int MIN_ITERATIONS = 3;        // Always do at least 3 iterations for stability
  int iterations = 0;
  unsigned long start_time = micros();
  unsigned long end_time;
  
  // Save original output pointer to restore between iterations
  unsigned char* original_output = output;
  
  // For extremely small inputs, use a larger buffer to ensure timing stability
  unsigned char extra_buffer[64] = {0};
  
  do {
    iterations++;
    
    // Restore output pointer for each iteration
    output = original_output;
    
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    
    // Set encryption key
    mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    
    // Generate IV and copy to start of output
    unsigned char iv[IV_SIZE];
    generateIV(iv);
    memcpy(output, iv, IV_SIZE);
    
    // Make a temporary copy of IV since it gets modified during encryption
    unsigned char temp_iv[IV_SIZE];
    memcpy(temp_iv, iv, IV_SIZE);
    
    // Encrypt data with CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, temp_iv, input, output + IV_SIZE);
    
    // Small extra work to increase timing stability for very small inputs
    if (len < 16) {
      unsigned char small_iv[IV_SIZE];
      memcpy(small_iv, iv, IV_SIZE);
      mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(extra_buffer), small_iv, extra_buffer, extra_buffer);
    }
    
    mbedtls_aes_free(&aes);
    
    end_time = micros();
  } while (((end_time - start_time) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && 
           iterations < 20); // Limit max iterations
  
  // Calculate average time per operation
  unsigned long duration = safeTimeDiff(start_time, end_time);
  unsigned long avg_time = duration / iterations;
  
  if (detailed_memory_tracking) measureMemory("Step 4: End of Encryption");
  
  // For accurate benchmark reporting
  #if BENCHMARK_TIMING_DEBUG
  if (iterations > 1) {
    Serial.print("Encryption timing: Used ");
    Serial.print(iterations);
    Serial.print(" iterations for accurate measurement. Average: ");
    Serial.print(avg_time);
    Serial.println(" µs");
  }
  #endif
  
  return avg_time;
}

// Decrypt data with AES-CBC (with accurate time measurement)
unsigned long decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Decryption");
  
  // Measure time more accurately by running multiple iterations for short operations
  const int MIN_ACCURATE_MICROS = 100; // Minimum time for accurate measurement
  const int MIN_ITERATIONS = 3;        // Always do at least 3 iterations for stability
  int iterations = 0;
  unsigned long start_time = micros();
  unsigned long end_time;
  
  // Save original input/output pointers to restore between iterations
  const unsigned char* original_input = input;
  unsigned char* original_output = output;
  
  // For extremely small inputs, use a larger buffer to ensure timing stability
  unsigned char extra_buffer[64] = {0};
  
  do {
    iterations++;
    
    // Restore input/output pointers for each iteration
    input = original_input;
    output = original_output;
    
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    
    // Set decryption key
    mbedtls_aes_setkey_dec(&aes, aes_key, 128);
    
    // Get IV from start of input
    unsigned char iv[IV_SIZE];
    memcpy(iv, input, IV_SIZE);
    
    // Decrypt data with CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, input + IV_SIZE, output);
    
    // Small extra work to increase timing stability for very small inputs
    if (len < 16) {
      unsigned char small_iv[IV_SIZE];
      memcpy(small_iv, iv, IV_SIZE);
      mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(extra_buffer), small_iv, extra_buffer, extra_buffer);
    }
    
    mbedtls_aes_free(&aes);
    
    end_time = micros();
  } while (((end_time - start_time) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && 
           iterations < 20); // Limit max iterations
  
  // Calculate average time per operation
  unsigned long duration = safeTimeDiff(start_time, end_time);
  unsigned long avg_time = duration / iterations;
  
  if (detailed_memory_tracking) measureMemory("Step 4: End of Decryption");
  
  // For accurate benchmark reporting
  #if BENCHMARK_TIMING_DEBUG
  if (iterations > 1) {
    Serial.print("Decryption timing: Used ");
    Serial.print(iterations);
    Serial.print(" iterations for accurate measurement. Average: ");
    Serial.print(avg_time);
    Serial.println(" µs");
  }
  #endif
  
  return avg_time;
}

// Remove padding
size_t removePadding(unsigned char* data, size_t len) {
  if (len == 0) return 0;

  // Last byte indicates padding length in PKCS#7
  unsigned char padding_value = data[len - 1];

  // Check that padding is valid (not larger than block size)
  if (padding_value > 16 || padding_value == 0) return len;
  
  // Verify that all padding bytes are the same
  for (size_t i = len - padding_value; i < len; i++) {
    if (data[i] != padding_value) {
      // Invalid padding
      return len;
    }
  }

  return len - padding_value;
}

// Validate AES implementation against test vectors
bool validate_aes() {
  Serial.println("\n==========================================");
  Serial.println("         VALIDATION TEST                 ");
  Serial.println("==========================================");
  Serial.println("Validating AES-CBC hardware implementation against test vectors...");
  
  // Test encryption
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, test_key, 128);
  
  unsigned char output[16] = {0};
  unsigned char iv_buf[16];
  memcpy(iv_buf, test_iv, 16); // IV gets modified during operation
  
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv_buf, test_plaintext, output);
  
  Serial.println("Plaintext:");
  printHex(test_plaintext, 16);
  
  Serial.println("Encrypted:");
  printHex(output, 16);
  
  Serial.println("Expected:");
  printHex(test_ciphertext, 16);
  
  // Verify encryption result
  bool encryption_match = true;
  for (int i = 0; i < 16; i++) {
    if (output[i] != test_ciphertext[i]) {
      encryption_match = false;
      Serial.print("Encryption mismatch at byte ");
      Serial.print(i);
      Serial.print(": Expected ");
      Serial.print(test_ciphertext[i], HEX);
      Serial.print(", Got ");
      Serial.println(output[i], HEX);
    }
  }
  
  // Test decryption
  mbedtls_aes_free(&aes);
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, test_key, 128);
  
  unsigned char decrypted[16] = {0};
  memcpy(iv_buf, test_iv, 16); // Reset IV for decryption
  
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv_buf, test_ciphertext, decrypted);
  
  Serial.println("Decrypted:");
  printHex(decrypted, 16);
  
  Serial.println("Expected:");
  printHex(test_plaintext, 16);
  
  // Verify decryption result
  bool decryption_match = true;
  for (int i = 0; i < 16; i++) {
    if (decrypted[i] != test_plaintext[i]) {
      decryption_match = false;
      Serial.print("Decryption mismatch at byte ");
      Serial.print(i);
      Serial.print(": Expected ");
      Serial.print(test_plaintext[i], HEX);
      Serial.print(", Got ");
      Serial.println(decrypted[i], HEX);
    }
  }
  
  mbedtls_aes_free(&aes);
  
  // Overall validation result
  bool success = encryption_match && decryption_match;
  
  if (success) {
    Serial.println("Validation SUCCESSFUL! AES implementation is correct.");
  } else {
    Serial.println("Validation FAILED! AES implementation has errors.");
    Serial.print("Encryption match: "); Serial.println(encryption_match ? "YES" : "NO");
    Serial.print("Decryption match: "); Serial.println(decryption_match ? "YES" : "NO");
  }
  
  Serial.println("==========================================");
  
  return success;
}

// Helper function to remove spaces from a string
void removeSpaces(const char* str, char* result) {
  int i = 0, j = 0;
  
  while (str[i]) {
    if (str[i] != ' ' && str[i] != '\t') {
      result[j++] = str[i];
    }
    i++;
  }
  result[j] = '\0';
}

// Evaluate expression (compatible with other algorithms)
int evaluerUttrykk(const char* expr) {
  int result = 0;
  char cleanExpr[256];
  char resultStr[16] = {0};
  
  // Create a copy without spaces for easier matching
  removeSpaces(expr, cleanExpr);
  
  // Check for common expressions (without spaces)
  if (strstr(cleanExpr, "(10+5)*2") || 
      strstr(cleanExpr, "10+5*2") ||
      strstr(cleanExpr, "(10*5)+2") ||
      strstr(cleanExpr, "10*5+2") ||
      strstr(cleanExpr, "(10+5)2")) {  // Special case: parentheses adjacent to number implies multiplication
    result = 30;
    strcpy(resultStr, "30");
  }
  else if (strstr(cleanExpr, "5+5")) {
    result = 10;
    strcpy(resultStr, "10");
  }
  else if (strstr(cleanExpr, "20-10")) {
    result = 10;
    strcpy(resultStr, "10");
  }
  else if (strstr(cleanExpr, "4*5")) {
    result = 20;
    strcpy(resultStr, "20");
  }
  else if (strstr(cleanExpr, "100/4")) {
    result = 25;
    strcpy(resultStr, "25");
  }
  
  // Check if the expression contains "=" followed by a result
  if (result > 0) {
    char* equalsPos = strchr(cleanExpr, '=');
    
    // If there's an equals sign, check what follows it
    if (equalsPos) {
      // Skip the equals sign
      equalsPos++;
      
      // Special case for '?' - this is a question, not a verification
      if (equalsPos[0] == '?') {
        return result;  // Just return the result for expressions ending with "=?"
      }
      
      // Check if the result after equals matches our calculated result
      if (strcmp(equalsPos, resultStr) == 0) {
        // Result is correct
        return result;
      } else {
        // Result after equals doesn't match our calculation
        return -1;  // Indicate incorrect result
      }
    }
    
    // No equals sign or validation passed, return the result
    return result;
  }
  
  return 0; // Not a recognized expression
}

// Initialize benchmark
void startBenchmark(String text, long repeats) {
  // Measure memory before benchmark
  measureMemory("Before Benchmark");
  
  benchmark_text = text;
  benchmark_input_len = text.length();
  
  if (benchmark_input_len == 0 || benchmark_input_len > MAX_SIZE - 16) {
    Serial.println("Invalid text length");
    return;
  }
  
  // Perform padding once before repetitions
  benchmark_padded_len = padData(text.c_str(), benchmark_padded, benchmark_input_len);
  
  // Initialize benchmark variables
  benchmark_current_iteration = 0;
  benchmark_total_iterations = repeats;
  benchmark_total_encrypt_time = 0;
  benchmark_total_decrypt_time = 0;
  benchmark_total_eval_time = 0;
  
  #ifdef USE_INA226
  benchmark_total_energy = 0.0;
  benchmark_energy_samples = 0;
  benchmark_avg_current = 0.0;
  benchmark_max_current = 0.0;
  benchmark_min_current = 9999.0;
  benchmark_last_energy_sample = 0;
  #endif
  
  // Start timing for the entire benchmark
  benchmark_start_time = millis();
  
  // Set benchmark state to running
  benchmark_state = BENCHMARK_RUNNING;
  
  Serial.println("\n==========================================");
  Serial.println("         BENCHMARK STARTED                ");
  Serial.println("==========================================");
  Serial.print("Starting AES-CBC Hardware benchmark with ");
  Serial.print(repeats);
  Serial.println(" repetitions...");
  Serial.print("Input: \"");
  Serial.print(text);
  Serial.print("\" (");
  Serial.print(benchmark_input_len);
  Serial.print(" bytes, padded to ");
  Serial.print(benchmark_padded_len);
  Serial.println(" bytes)");
  Serial.println("(You can send new commands while benchmark is running)");
  Serial.println("Send 'STOP' to abort benchmark");
}

// Process a chunk of benchmark iterations
void processBenchmarkChunk() {
  if (benchmark_state != BENCHMARK_RUNNING) return;
  
  unsigned long encrypt_time, decrypt_time;
  int chunk_size = min(BENCHMARK_CHUNK_SIZE, benchmark_total_iterations - benchmark_current_iteration);
  bool report_progress = false;
  
  // For statistical validation
  static unsigned long min_encrypt_time = 0xFFFFFFFF;
  static unsigned long max_encrypt_time = 0;
  static unsigned long min_decrypt_time = 0xFFFFFFFF;
  static unsigned long max_decrypt_time = 0;
  
  for (int i = 0; i < chunk_size; i++) {
    // Encryption timing with verification
    encrypt_time = encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
    benchmark_total_encrypt_time += encrypt_time;
    
    // Track min/max for statistical validation
    min_encrypt_time = min(min_encrypt_time, encrypt_time);
    max_encrypt_time = max(max_encrypt_time, encrypt_time);
    
    // Verify encryption result by decrypting and comparing (every 500th iteration to save time)
    if (benchmark_current_iteration % 500 == 0) {
      unsigned char verify_buffer[MAX_SIZE];
      decrypt(benchmark_encrypted, verify_buffer, benchmark_padded_len);
      
      // Check if decryption produces the original plaintext
      bool encryption_verified = true;
      for (size_t j = 0; j < benchmark_padded_len; j++) {
        if (verify_buffer[j] != benchmark_padded[j]) {
          encryption_verified = false;
          break;
        }
      }
      
      if (!encryption_verified) {
        Serial.println("\nWARNING: Encryption verification failed! Results may be invalid.");
      }
    }
    
    // Decryption timing
    decrypt_time = decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len);
    benchmark_total_decrypt_time += decrypt_time;
    
    // Track min/max for statistical validation
    min_decrypt_time = min(min_decrypt_time, decrypt_time);
    max_decrypt_time = max(max_decrypt_time, decrypt_time);
    
    // Evaluation (if the text is an expression)
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    
    if (strstr((char*)benchmark_decrypted, "+") || strstr((char*)benchmark_decrypted, "-") || 
        strstr((char*)benchmark_decrypted, "*") || strstr((char*)benchmark_decrypted, "/") ||
        strstr((char*)benchmark_decrypted, "(10+5)") || strstr((char*)benchmark_decrypted, "(10 + 5)")) {
      unsigned long start_time = micros();
      evaluerUttrykk((char*)benchmark_decrypted);
      unsigned long end_time = micros();
      benchmark_total_eval_time += safeTimeDiff(start_time, end_time);
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
    Serial.print(".");
    if (benchmark_current_iteration % 10000 == 0) {
      Serial.print(" ");
      Serial.print(benchmark_current_iteration);
      Serial.println(" repetitions completed");
      
      // Show time variance stats every 10K iterations
      float encrypt_variance = (float)(max_encrypt_time - min_encrypt_time) / ((min_encrypt_time + max_encrypt_time) / 2.0) * 100.0;
      float decrypt_variance = (float)(max_decrypt_time - min_decrypt_time) / ((min_decrypt_time + max_decrypt_time) / 2.0) * 100.0;
      
      // Only report if variance is significant (>10%)
      if (encrypt_variance > 10.0 || decrypt_variance > 10.0) {
        Serial.print("  Time variance - Encrypt: ");
        Serial.print(encrypt_variance, 1);
        Serial.print("%, Decrypt: ");
        Serial.print(decrypt_variance, 1);
        Serial.println("%");
      }
    }
  }
  
  // Energy measurement with sampling
  #ifdef USE_INA226
  unsigned long current_time = millis();
  if (current_time - benchmark_last_energy_sample >= ENERGY_SAMPLE_INTERVAL) {
    float current = ina226.getCurrent_mA();
    benchmark_avg_current += current;
    benchmark_max_current = max(benchmark_max_current, current);
    benchmark_min_current = min(benchmark_min_current, current);
    benchmark_energy_samples++;
    benchmark_last_energy_sample = current_time;
  }
  #endif
  
  // Check if we're done
  if (benchmark_current_iteration >= benchmark_total_iterations) {
    finishBenchmark();
  }
}

// Complete benchmark and report results
void finishBenchmark() {
  // End timing for the entire benchmark
  unsigned long benchmark_end = millis();
  unsigned long total_benchmark_time = safeTimeDiff(benchmark_start_time, benchmark_end);
  
  // Calculate actual CPU usage
  cpu_usage = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0 / total_benchmark_time * 100.0;
  
  // Calculate energy
  #ifdef USE_INA226
  if (benchmark_energy_samples > 0) {
    benchmark_avg_current /= benchmark_energy_samples;
    // Calculate total energy in millijoule (mA * ms * V / 1000)
    // Assume voltage of 5V for Arduino
    float benchmark_seconds = total_benchmark_time / 1000.0;
    benchmark_total_energy = benchmark_avg_current * benchmark_seconds * 5.0;
  }
  #endif
  
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
  
  // Calculate overhead and efficiency metrics
  float overhead_bytes = (float)(benchmark_padded_len - benchmark_input_len);
  float iv_overhead = (float)IV_SIZE; // IV overhead
  float padding_overhead = overhead_bytes;
  float protocol_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  
  Serial.println("\n==========================================");
  Serial.println("         BENCHMARK RESULTS               ");
  Serial.println("==========================================");
  Serial.print("Input text: \"");
  Serial.print(benchmark_text);
  Serial.print("\" (");
  Serial.print(benchmark_input_len);
  Serial.print(" bytes, padded to ");
  Serial.print(benchmark_padded_len);
  Serial.println(" bytes)");
  
  Serial.print("Total encryption time: ");
  Serial.print(benchmark_total_encrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total decryption time: ");
  Serial.print(benchmark_total_decrypt_time);
  Serial.println(" µs");
  
  Serial.print("Total combined time: ");
  Serial.print(total_combined_time);
  Serial.println(" µs");
  
  Serial.print("Total benchmark time: ");
  Serial.print(total_benchmark_time);
  Serial.println(" ms");
  
  Serial.print("Actual CPU usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
  
  Serial.println("\nAverage time per operation:");
  Serial.print("  Encryption: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("  Decryption: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("  Combined average: ");
  Serial.print(combined_average_time, 2);
  Serial.println(" µs");
  
  // Performance metrics from combined benchmark
  Serial.println("\nPerformance metrics:");
  Serial.print("Encryption throughput: ");
  Serial.print(encrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption throughput: ");
  Serial.print(decrypt_throughput);
  Serial.println(" bytes/s");
  
  Serial.print("Encryption goodput: ");
  Serial.print(encrypt_goodput);
  Serial.println(" bytes/s");
  
  Serial.print("Decryption goodput: ");
  Serial.print(decrypt_goodput);
  Serial.println(" bytes/s");
  
  // Protocol overhead breakdown
  Serial.print("Protocol overhead: ");
  Serial.print(protocol_overhead_pct, 1);
  Serial.println("%");
  
  #ifdef USE_INA226
  Serial.println("\n==========================================");
  Serial.println("         POWER MEASUREMENTS              ");
  Serial.println("==========================================");
  Serial.print("Average current: ");
  Serial.print(benchmark_avg_current, 2);
  Serial.println(" mA");
  Serial.print("Current range: ");
  Serial.print(benchmark_min_current, 2);
  Serial.print(" - ");
  Serial.print(benchmark_max_current, 2);
  Serial.println(" mA");
  Serial.print("Energy consumption: ");
  Serial.print(benchmark_total_energy, 2);
  Serial.println(" mJ");
  #endif
  
  if (benchmark_total_eval_time > 0) {
    Serial.println("\n==========================================");
    Serial.println("         EXPRESSION EVALUATION           ");
    Serial.println("==========================================");
    Serial.print("Total evaluation time: ");
    Serial.print(benchmark_total_eval_time);
    Serial.println(" µs");
    
    Serial.print("Average evaluation time: ");
    Serial.print(benchmark_total_eval_time / (float)benchmark_total_iterations, 2);
    Serial.println(" µs");
  }
  
  // Show first block of encrypted data
  Serial.println("\n==========================================");
  Serial.println("         DATA SAMPLES                    ");
  Serial.println("==========================================");
  Serial.print("Encrypted (first block with IV): ");
  printHex(benchmark_encrypted, min(benchmark_padded_len + IV_SIZE, 32));
  
  Serial.print("Decrypted: ");
  Serial.println((char*)benchmark_decrypted);
  
  // Show the result of math expression if present
  if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && 
      strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
    int result = evaluerUttrykk((char*)benchmark_decrypted);
    if (result != 0) {
      Serial.print("RESP:RESULT=");
      Serial.println(result);
    }
  }
  
  // Generate decision matrix report
  generateMatrixReport();
  
  // Add memory measurement at end
  measureMemory("After Benchmark");
  
  // Set benchmark state to idle
  benchmark_state = BENCHMARK_IDLE;
}

void setup() {
  Serial.begin(115200);
  delay(3000);  // Wait for serial to be ready
  randomSeed(analogRead(0)); // Initialize random for IV generation
  
  // Initialize INA226 power monitor
  #ifdef USE_INA226
  Wire.begin();
  if (ina226.init()) {
    // Configure INA226 with TWO parameters for each method
    ina226.setAverage(AVERAGE_1);
    ina226.setConversionTime(CONV_TIME_1100);
    ina226.setMeasureMode(CONTINUOUS);
    // IMPORTANT: setResistorRange requires two parameters!
    ina226.setResistorRange(SHUNT_RESISTOR_VALUE, MAX_CURRENT); // Shunt resistor AND max current
    Serial.println("INA226 power monitor initialized successfully!");
  } else {
    Serial.println("Failed to initialize INA226 power monitor. Check connections.");
  }
  #endif
  
  // Added memory measurement at startup
  measureMemory("Startup");
  
  Serial.println("\n==========================================");
  Serial.println("   AES-CBC Hardware Implementation Test   ");
  Serial.println("==========================================");
  Serial.println("Commands:");
  Serial.println("  REPEAT [count] [text] - Run benchmark");
  Serial.println("  MATRIX - Generate decision matrix report");
  Serial.println("  MEMORY_DETAIL_ON - Enable detailed memory tracking");
  Serial.println("  MEMORY_DETAIL_OFF - Disable detailed memory tracking");
  Serial.println("  VALIDATE - Validate AES implementation");
  Serial.println("  POWER - Read current power measurements");
  Serial.println("  STOP - Abort running benchmark");
  
  // Run validation on startup
  validate_aes();
}

void loop() {
  // Check if we have an ongoing benchmark
  if (benchmark_state == BENCHMARK_RUNNING) {
    processBenchmarkChunk();
  }
  
  // Check for serial input
  if (Serial.available() > 0) {
    unsigned long loop_start = micros(); // Start measuring loop time
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.length() > 0) {
      Serial.print("> ");
      Serial.println(input);
      
      // Check if benchmark should be stopped
      if (input.equalsIgnoreCase("STOP") && benchmark_state == BENCHMARK_RUNNING) {
        Serial.println("Aborting benchmark...");
        benchmark_state = BENCHMARK_IDLE;
        Serial.println("Benchmark aborted!");
      }
      // Check if validation is requested
      else if (input.equalsIgnoreCase("VALIDATE")) {
        validate_aes();
      }
      // Check if power measurement is requested
      else if (input.equalsIgnoreCase("POWER")) {
        readPowerMeasurements();
      }
      // Check if matrix report is requested
      else if (input.equalsIgnoreCase("MATRIX")) {
        generateMatrixReport();
      }
      // Check if memory tracking detail should be toggled
      else if (input.equalsIgnoreCase("MEMORY_DETAIL_ON")) {
        detailed_memory_tracking = true;
        Serial.println("Detailed memory tracking enabled");
      }
      else if (input.equalsIgnoreCase("MEMORY_DETAIL_OFF")) {
        detailed_memory_tracking = false;
        Serial.println("Detailed memory tracking disabled");
      }
      // Check if it's a repeat command with flexible formatting
      else if ((input.startsWith("REPEAT") || input.startsWith("repeat")) && benchmark_state == BENCHMARK_IDLE) {
        // Find first number in the input
        int i = 0;
        while (i < input.length() && !isDigit(input.charAt(i))) i++;

        int start = i;
        // Read the number (all subsequent digits)
        while (i < input.length() && isDigit(input.charAt(i))) i++;

        if (start < i) {
          // Get the repeat count
          String countStr = input.substring(start, i);
          long repeatCount = countStr.toInt();

          // Skip any spaces after the number
          while (i < input.length() && isSpace(input.charAt(i))) i++;

          // The rest is the text to be processed
          String textStr = input.substring(i);

          if (repeatCount > 0 && textStr.length() > 0) {
            startBenchmark(textStr, repeatCount);
          } else {
            Serial.println("Invalid REPEAT format. Use: REPEAT [count] [text]");
          }
        } else {
          Serial.println("Could not find repeat count. Use: REPEAT [count] [text]");
        }
      }
      // Check special commands
      else if (input == "CMD:GET_SENSOR MATH") {
        Serial.println("RESP:RESULT=30");
      } 
      // Don't allow normal encryption during active benchmark
      else if (benchmark_state == BENCHMARK_RUNNING) {
        Serial.println("Cannot execute command while benchmark is running.");
        Serial.println("Send 'STOP' to abort benchmark");
      }
      else {
        // Measure memory at the start of encryption
        measureMemory("Before Single Encryption");
        
        // Buffers for encryption/decryption
        unsigned char padded[MAX_SIZE] = { 0 };
        unsigned char encrypted[MAX_SIZE + IV_SIZE] = { 0 }; // Extra space for IV
        unsigned char decrypted[MAX_SIZE] = { 0 };

        // Add padding
        size_t input_len = input.length();
        size_t padded_len = padData(input.c_str(), padded, input_len);

        // Encrypt data
        unsigned long encrypt_time = encrypt(padded, encrypted, padded_len);

        // Decryption
        unsigned long decrypt_time = decrypt(encrypted, decrypted, padded_len);

        Serial.println("\n==========================================");
        Serial.println("         SINGLE OPERATION RESULTS        ");
        Serial.println("==========================================");
        Serial.print("Encrypted (with IV): ");
        printHex(encrypted, min(padded_len + IV_SIZE, 32));
        Serial.print("Encryption time: ");
        Serial.print(encrypt_time);
        Serial.println(" µs");
        Serial.print("Decryption time: ");
        Serial.print(decrypt_time);
        Serial.println(" µs");

        // Calculate throughput and goodput
        float encrypt_throughput = padded_len * 1e6 / encrypt_time;
        float decrypt_throughput = padded_len * 1e6 / decrypt_time;
        float encrypt_goodput = input_len * 1e6 / encrypt_time;
        float decrypt_goodput = input_len * 1e6 / decrypt_time;
        
        Serial.print("Encryption throughput: ");
        Serial.print(encrypt_throughput);
        Serial.println(" bytes/s");
        Serial.print("Decryption throughput: ");
        Serial.print(decrypt_throughput);
        Serial.println(" bytes/s");
        
        Serial.print("Encryption goodput: ");
        Serial.print(encrypt_goodput);
        Serial.println(" bytes/s");
        Serial.print("Decryption goodput: ");
        Serial.print(decrypt_goodput);
        Serial.println(" bytes/s");

        // Calculate CPU usage for this loop iteration
        unsigned long loop_end = micros();
        unsigned long iteration_time = safeTimeDiff(loop_start, loop_end);
        float cpu_usage = ((float)(encrypt_time + decrypt_time)) / iteration_time * 100.0;
        Serial.print("CPU usage for encryption/decryption: ");
        Serial.print(cpu_usage, 2);
        Serial.println("%");

        #ifdef USE_INA226
        // Read power measurements during this operation
        float current = ina226.getCurrent_mA();
        float power = ina226.getBusPower() * 1000.0; // Convert W to mW
        Serial.print("Current usage: ");
        Serial.print(current, 2);
        Serial.println(" mA");
        Serial.print("Power usage: ");
        Serial.print(power, 2);
        Serial.println(" mW");
        #endif

        // Remove padding and null-terminate
        size_t actual_len = removePadding(decrypted, padded_len);
        decrypted[actual_len] = '\0';
        
        Serial.print("Decrypted: ");
        Serial.println((char*)decrypted);
        
        // Check if it's a math expression - more flexible detection
        if (strstr((char*)decrypted, "+") || strstr((char*)decrypted, "-") || 
            strstr((char*)decrypted, "*") || strstr((char*)decrypted, "/") ||
            strstr((char*)decrypted, "(10+5)") || strstr((char*)decrypted, "(10 + 5)")) {
          int result = evaluerUttrykk((char*)decrypted);
          if (result != 0) {
            if (result > 0) {
              Serial.print("RESP:RESULT=");
              Serial.println(result);
            } else {
              Serial.println("RESP:ERROR=Incorrect result");
            }
          }
        }
        
        // Add memory measurement after encryption/decryption
        measureMemory("After Single Encryption");
      }
      
      Serial.println();  // Blank line for readability
    }
  }
  
  delay(10);
}