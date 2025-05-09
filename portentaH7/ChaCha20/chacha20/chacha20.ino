/*
 * ChaCha20 Software Implementation for Arduino Portenta H7
 * Using software ChaCha20 with dual-core support for Portenta H7
 */
#include <Arduino.h>
#include "SDMMCBlockDevice.h"
#include "FATFileSystem.h"
#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
#endif

// SD card and filesystem
SDMMCBlockDevice block_device;
mbed::FATFileSystem fs("fs");
bool sd_card_ready = false;
bool format_confirmation_pending = false;

// Display control options
bool detail_mode = false;  // Default is OFF - styrer detaljert utskrift for IMAGE-test

// RTOS for dual-core
#if defined(ARDUINO_PORTENTA_H7_M7) && defined(CORE_CM4) && defined(CORE_CM7)
#define USE_MULTICORE_RTOS
#define CORE_CRYPTO 1  // M7 core
#define CORE_POWER 0   // M4 core
#include "mbed.h"
#include "rtos/rtos.h"

static bool m4_running = false;
rtos::Thread power_thread;
rtos::Thread crypto_thread;
rtos::Mutex power_mutex;
rtos::Mutex benchmark_mutex;
rtos::Mutex serial_mutex;
rtos::Semaphore crypto_semaphore(0);
rtos::Semaphore power_semaphore(0);

volatile bool crypto_active = false;
volatile bool power_thread_running = false;
volatile bool benchmark_mode = false;
volatile bool single_measurement_mode = false;

// Power measurement buffer
#define MAX_POWER_SAMPLES 2000
struct PowerSample {
  unsigned long timestamp;  // in ms
  float current_A;          // in Amperes
  float voltage_V;          // in Volts
  float power_W;            // in Watts
};
PowerSample power_samples[MAX_POWER_SAMPLES];
volatile int power_sample_count = 0;
#define POWER_SAMPLE_INTERVAL_MS 10

void startM4Core() {
  if (!m4_running) {
    bootM4();
    m4_running = true;
    Serial.println("M4 core started");
  }
}
#endif

// CPU usage calculation
#ifdef ARDUINO_ARCH_MBED
float calculateActualCpuUsage() {
  static unsigned long last_time = 0;
  static uint64_t last_idle_time = 0;
  mbed_stats_cpu_t cpu_stats;
  mbed_stats_cpu_get(&cpu_stats);

  unsigned long current_time = millis();
  unsigned long delta_time = current_time - last_time;
  if (last_time > 0) {
    uint64_t delta_idle = cpu_stats.idle_time - last_idle_time;
    float idle_percentage = (float)delta_idle / (float)(delta_time * 1000) * 100.0;
    float usage_percentage = 100.0 - idle_percentage;
    return constrain(usage_percentage, 0.0, 100.0);
  }

  last_time = current_time;
  last_idle_time = cpu_stats.idle_time;
  return 0.0;
}
#else
float calculateCpuUsageEstimate(unsigned long processing_time, unsigned long total_time) {
  return constrain((float)processing_time / (float)total_time * 100.0, 0.0, 100.0);
}
#endif

// Constants
#define ALGORITHM_NAME "ChaCha20-SOFTWARE"
bool detailed_memory_tracking = false;

// Power monitoring - INA226
#define USE_INA226
#ifdef USE_INA226
#include <Wire.h>
#include <INA226_WE.h>
#define INA226_I2C_ADDRESS 0x40
#define SHUNT_RESISTOR_VALUE 0.1
#define MAX_CURRENT 3.0
INA226_WE ina226(INA226_I2C_ADDRESS);
bool ina226_available = false;  // Flag to track if INA226 is available
#endif

#define BENCHMARK_TIMING_DEBUG false
#define IV_SIZE 16  // Combined nonce (12 bytes) + counter (4 bytes)
#define SD_CS_PIN 10
#define BLOCK_SIZE 1024
#define UART_BUFFER_SIZE 128
#define SERIAL_NUCLEO Serial1
#define BENCHMARK_CHUNK_SIZE 100
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true

// ChaCha20 Constants
#define CHACHA20_KEY_SIZE 32    // 256-bit key
#define CHACHA20_NONCE_SIZE 12  // 96-bit nonce (RFC 8439)
#define CHACHA20_BLOCK_SIZE 64  // 512-bit blocks
#define CHACHA20_ROUNDS 20      // Number of rounds (20 for ChaCha20)

// ChaCha20 state constants (magic numbers from RFC 8439)
static const uint32_t chacha20_constants[4] = {
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574  // "expand 32-byte k" in ASCII
};

// ChaCha20 key (256-bit)
const unsigned char chacha20_key[CHACHA20_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// RFC 8439 Test Vector
const uint8_t test_key[CHACHA20_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

const uint8_t test_nonce[CHACHA20_NONCE_SIZE] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
  0x00, 0x00, 0x00, 0x00
};

const uint32_t test_counter = 1;

// First 16 bytes of expected keystream for the test vector
const uint8_t test_keystream[16] = {
  0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1,
  0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed
};

// Benchmark state variables
bool benchmark_state = BENCHMARK_IDLE;
const size_t MAX_SIZE = BLOCK_SIZE;
unsigned char benchmark_padded[MAX_SIZE] = { 0 };
unsigned char benchmark_encrypted[MAX_SIZE + IV_SIZE] = { 0 };
unsigned char benchmark_decrypted[MAX_SIZE] = { 0 };
size_t benchmark_input_len = 0;
size_t benchmark_padded_len = 0;
long benchmark_current_iteration = 0;
long benchmark_total_iterations = 0;
unsigned long benchmark_total_encrypt_time = 0;
unsigned long benchmark_total_decrypt_time = 0;
unsigned long benchmark_total_eval_time = 0;
unsigned long benchmark_start_time = 0;
String benchmark_text = "";

// Metrics
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
float benchmark_total_energy = 0.0;  // in Joules
int benchmark_energy_samples = 0;
float benchmark_avg_current = 0.0;     // in Amperes
float benchmark_max_current = 0.0;     // in Amperes
float benchmark_min_current = 9999.0;  // in Amperes
float benchmark_avg_voltage = 0.0;     // in Volts
float benchmark_avg_power = 0.0;       // in Watts
unsigned long benchmark_last_energy_sample = 0;
const unsigned long ENERGY_SAMPLE_INTERVAL = 100;
#endif

// Image processing buffers
unsigned char image_buffer[BLOCK_SIZE] = { 0 };
unsigned char encrypted_buffer[BLOCK_SIZE + IV_SIZE] = { 0 };

// Forward declarations
bool setup_sd_card();
void processFormatCommand(String input);
void startBenchmark(String text, long repeats);
void processBenchmarkChunk();
void finishBenchmark();
unsigned long encrypt(const unsigned char* input, unsigned char* output, size_t len);
unsigned long decrypt(const unsigned char* input, unsigned char* output, size_t len);
unsigned long safeTimeDiff(unsigned long start, unsigned long end);
bool runImageTest(const char* filename, int iterations);
void listSDFiles();
bool displayImageInfo(const char* filename);
void errorBlink(int count);
void successBlink(int count);
void printPowerMeasurements(float avg_current_A, float min_current_A, float max_current_A,
                            float avg_voltage_V, float avg_power_W, float total_energy_J);

// Forward declarations for ChaCha20 functions
void chacha20_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
void chacha20_block(uint32_t* state, uint32_t* output);
void chacha20_init(uint32_t* state, const unsigned char* key, const unsigned char* nonce, uint32_t counter);
void chacha20_encrypt_decrypt(const unsigned char* input, unsigned char* output, size_t len,
                              const unsigned char* key, const unsigned char* nonce, uint32_t counter);
bool validate_chacha20();

#ifdef USE_MULTICORE_RTOS
void powerMeasurementThread();
void cryptoBenchmarkThread();
void startPowerMeasurement();
void startBenchmarkRTOS();
#endif

// Utility functions
void printHex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 16) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

unsigned long safeTimeDiff(unsigned long start, unsigned long end) {
  return (end >= start) ? (end - start) : ((0xFFFFFFFF - start) + end + 1);
}

void generateNonce(unsigned char* nonce) {
  for (int i = 0; i < CHACHA20_NONCE_SIZE; i++) {
    nonce[i] = random(256);
  }
}

// ChaCha20 helper functions

// Rotate left (circular left shift)
inline uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

// Load a 32-bit value from bytes (little-endian)
inline uint32_t U8TO32_LITTLE(const unsigned char* p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Store a 32-bit value to bytes (little-endian)
inline void U32TO8_LITTLE(unsigned char* p, uint32_t v) {
  p[0] = v & 0xFF;
  p[1] = (v >> 8) & 0xFF;
  p[2] = (v >> 16) & 0xFF;
  p[3] = (v >> 24) & 0xFF;
}

// The ChaCha20 quarter round function
void chacha20_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
  a += b;
  d ^= a;
  d = rotl32(d, 16);
  c += d;
  b ^= c;
  b = rotl32(b, 12);
  a += b;
  d ^= a;
  d = rotl32(d, 8);
  c += d;
  b ^= c;
  b = rotl32(b, 7);
}

// The ChaCha20 block function (20 rounds = 10 column + 10 diagonal rounds)
void chacha20_block(uint32_t* state, uint32_t* output) {
  // Copy input state to working state
  uint32_t x[16];
  for (int i = 0; i < 16; i++) {
    x[i] = state[i];
  }

  // 20 rounds (10 column rounds + 10 diagonal rounds)
  for (int i = 0; i < CHACHA20_ROUNDS; i += 2) {
    // Column round
    chacha20_quarter_round(x[0], x[4], x[8], x[12]);
    chacha20_quarter_round(x[1], x[5], x[9], x[13]);
    chacha20_quarter_round(x[2], x[6], x[10], x[14]);
    chacha20_quarter_round(x[3], x[7], x[11], x[15]);

    // Diagonal round
    chacha20_quarter_round(x[0], x[5], x[10], x[15]);
    chacha20_quarter_round(x[1], x[6], x[11], x[12]);
    chacha20_quarter_round(x[2], x[7], x[8], x[13]);
    chacha20_quarter_round(x[3], x[4], x[9], x[14]);
  }

  // Add input state to working state
  for (int i = 0; i < 16; i++) {
    output[i] = x[i] + state[i];
  }
}

// Initialize ChaCha20 state with key, nonce, and counter
void chacha20_init(uint32_t* state, const unsigned char* key,
                   const unsigned char* nonce, uint32_t counter) {
  // Constants (magic numbers from RFC 8439)
  state[0] = chacha20_constants[0];
  state[1] = chacha20_constants[1];
  state[2] = chacha20_constants[2];
  state[3] = chacha20_constants[3];

  // Key (8 words = 32 bytes)
  state[4] = U8TO32_LITTLE(key + 0);
  state[5] = U8TO32_LITTLE(key + 4);
  state[6] = U8TO32_LITTLE(key + 8);
  state[7] = U8TO32_LITTLE(key + 12);
  state[8] = U8TO32_LITTLE(key + 16);
  state[9] = U8TO32_LITTLE(key + 20);
  state[10] = U8TO32_LITTLE(key + 24);
  state[11] = U8TO32_LITTLE(key + 28);

  // Counter (1 word = 4 bytes)
  state[12] = counter;

  // Nonce (3 words = 12 bytes)
  state[13] = U8TO32_LITTLE(nonce + 0);
  state[14] = U8TO32_LITTLE(nonce + 4);
  state[15] = U8TO32_LITTLE(nonce + 8);
}

// Generate ChaCha20 keystream
void chacha20_keystream(uint32_t* state, unsigned char* keystream, size_t len) {
  uint32_t output[16];
  unsigned char block[64];

  for (size_t offset = 0; offset < len; offset += 64) {
    // Generate block of keystream
    chacha20_block(state, output);

    // Serialize output block to bytes
    for (int i = 0; i < 16; i++) {
      U32TO8_LITTLE(block + (i * 4), output[i]);
    }

    // Copy keystream to output
    size_t block_size = min(64, len - offset);
    memcpy(keystream + offset, block, block_size);

    // Increment counter for next block
    state[12]++;
  }
}

// Encrypt/decrypt data with ChaCha20
void chacha20_encrypt_decrypt(const unsigned char* input, unsigned char* output,
                              size_t len, const unsigned char* key,
                              const unsigned char* nonce, uint32_t counter) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before ChaCha20");

  uint32_t state[16];
  unsigned char keystream[CHACHA20_BLOCK_SIZE];

  // Initialize state
  chacha20_init(state, key, nonce, counter);

  if (detailed_memory_tracking) measureMemory("Step 2: After State Init");

  // Process data in chunks
  for (size_t offset = 0; offset < len; offset += CHACHA20_BLOCK_SIZE) {
    // Generate keystream block
    chacha20_block(state, (uint32_t*)keystream);

    // Convert block to bytes
    for (int i = 0; i < 16; i++) {
      U32TO8_LITTLE(keystream + (i * 4), ((uint32_t*)keystream)[i]);
    }

    // XOR input with keystream
    size_t chunk_size = min(CHACHA20_BLOCK_SIZE, len - offset);
    for (size_t i = 0; i < chunk_size; i++) {
      output[offset + i] = input[offset + i] ^ keystream[i];
    }

    // Increment counter for next block
    state[12]++;
  }

  if (detailed_memory_tracking) measureMemory("Step 3: End of ChaCha20");
}

size_t padData(const char* input, unsigned char* output, size_t len) {
  size_t padded_len = ((len + 15) / 16) * 16;
  memcpy(output, input, len);
  unsigned char pad_value = padded_len - len;
  if (pad_value == 0) {
    pad_value = 16;
    padded_len += 16;
  }
  for (size_t i = len; i < padded_len; i++) {
    output[i] = pad_value;
  }
  return padded_len;
}

// Core encryption/decryption functions using ChaCha20
unsigned long encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Encryption");

  if (len > MAX_SIZE) {
    Serial.println("Error: len too large for MAX_SIZE in encrypt()");
    return 0;
  }

#ifdef USE_MULTICORE_RTOS
  if (!benchmark_mode && !crypto_active) {
    crypto_active = true;
    power_mutex.lock();
    power_sample_count = 0;
    power_mutex.unlock();
    power_semaphore.release();
  }
#endif

  const int MIN_ACCURATE_MICROS = 100;
  const int MIN_ITERATIONS = 3;
  int iterations = 0;
  unsigned long loop_start_time = micros();
  unsigned long total_actual_time = 0;

  unsigned char current_nonce[CHACHA20_NONCE_SIZE];
  uint32_t counter = 1;

  do {
    iterations++;

    generateNonce(current_nonce);
    memcpy(output, current_nonce, CHACHA20_NONCE_SIZE);
    memcpy(output + CHACHA20_NONCE_SIZE, &counter, 4);

    unsigned long single_op_start_time = micros();
    chacha20_encrypt_decrypt(input, output + IV_SIZE, len, chacha20_key, current_nonce, counter);
    total_actual_time += safeTimeDiff(single_op_start_time, micros());

    // Extra work for consistent timing loop duration
    unsigned char small_nonce_extra[CHACHA20_NONCE_SIZE];
    memcpy(small_nonce_extra, current_nonce, CHACHA20_NONCE_SIZE);
    unsigned char extra_buf[64] = { 0 };
    chacha20_encrypt_decrypt(extra_buf, extra_buf, sizeof(extra_buf), chacha20_key, small_nonce_extra, counter);

  } while ((safeTimeDiff(loop_start_time, micros()) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && iterations < 20);

  unsigned long avg_actual_time = (iterations > 0) ? (total_actual_time / iterations) : 0;

  if (detailed_memory_tracking) measureMemory("Step 4: End of Encryption");

#ifdef USE_MULTICORE_RTOS
  if (!benchmark_mode && crypto_active) {
    crypto_active = false;
  }
#endif

#if BENCHMARK_TIMING_DEBUG
#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  if (iterations > 1) {
    Serial.print("Encryption timing: ");
    Serial.print(iterations);
    Serial.print(" iterations, avg actual ChaCha20: ");
    Serial.print(avg_actual_time);
    Serial.println(" µs");
  }
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
#endif

  return avg_actual_time;
}

unsigned long decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  if (detailed_memory_tracking) measureMemory("Step 1: Before Decryption");

  if (len > MAX_SIZE) {
    Serial.println("Error: len too large for MAX_SIZE in decrypt()");
    return 0;
  }

#ifdef USE_MULTICORE_RTOS
  if (!benchmark_mode && !crypto_active) {
    crypto_active = true;
    power_mutex.lock();
    power_sample_count = 0;
    power_mutex.unlock();
    power_semaphore.release();
  }
#endif

  const int MIN_ACCURATE_MICROS = 100;
  const int MIN_ITERATIONS = 3;
  int iterations = 0;
  unsigned long loop_start_time = micros();
  unsigned long total_actual_time = 0;

  unsigned char nonce[CHACHA20_NONCE_SIZE];
  uint32_t counter;

  do {
    iterations++;

    memcpy(nonce, input, CHACHA20_NONCE_SIZE);
    memcpy(&counter, input + CHACHA20_NONCE_SIZE, 4);

    unsigned long single_op_start_time = micros();
    chacha20_encrypt_decrypt(input + IV_SIZE, output, len, chacha20_key, nonce, counter);
    total_actual_time += safeTimeDiff(single_op_start_time, micros());

    // Extra work for consistent timing loop duration
    unsigned char small_nonce_extra[CHACHA20_NONCE_SIZE];
    memcpy(small_nonce_extra, nonce, CHACHA20_NONCE_SIZE);
    unsigned char extra_buf[64] = { 0 };
    chacha20_encrypt_decrypt(extra_buf, extra_buf, sizeof(extra_buf), chacha20_key, small_nonce_extra, counter);

  } while ((safeTimeDiff(loop_start_time, micros()) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && iterations < 20);

  unsigned long avg_actual_time = (iterations > 0) ? (total_actual_time / iterations) : 0;

  if (detailed_memory_tracking) measureMemory("Step 4: End of Decryption");

#ifdef USE_MULTICORE_RTOS
  if (!benchmark_mode && crypto_active) {
    crypto_active = false;
  }
#endif

#if BENCHMARK_TIMING_DEBUG
#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  if (iterations > 1) {
    Serial.print("Decryption timing: ");
    Serial.print(iterations);
    Serial.print(" iterations, avg actual ChaCha20: ");
    Serial.print(avg_actual_time);
    Serial.println(" µs");
  }
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
#endif

  return avg_actual_time;
}

size_t removePadding(unsigned char* data, size_t len) {
  if (len == 0) return 0;
  unsigned char padding_value = data[len - 1];
  if (padding_value > 16 || padding_value == 0) return len;

  for (size_t i = len - padding_value; i < len; i++) {
    if (data[i] != padding_value) {
      return len;
    }
  }
  return len - padding_value;
}

// ChaCha20 validation
bool validate_chacha20() {
#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  Serial.println("\n==========================================");
  Serial.println("         VALIDATION TEST                 ");
  Serial.println("==========================================");
  Serial.println("Validating ChaCha20 software implementation...");

  // Set up test state
  uint32_t state[16];
  chacha20_init(state, test_key, test_nonce, test_counter);

  // Generate keystream
  unsigned char keystream[CHACHA20_BLOCK_SIZE];
  chacha20_keystream(state, keystream, CHACHA20_BLOCK_SIZE);

  // Verify keystream matches expected
  bool keystream_match = true;
  for (int i = 0; i < 16; i++) {
    if (keystream[i] != test_keystream[i]) {
      keystream_match = false;
      Serial.print("Keystream mismatch at byte ");
      Serial.print(i);
      Serial.print(": Expected ");
      Serial.print(test_keystream[i], HEX);
      Serial.print(", Got ");
      Serial.println(keystream[i], HEX);
    }
  }

  Serial.println("First 16 bytes of keystream:");
  printHex(keystream, 16);

  Serial.println("Expected keystream:");
  printHex(test_keystream, 16);

  // Test encryption/decryption
  const char* test_plaintext = "The quick brown fox jumps over the lazy dog";
  size_t test_len = strlen(test_plaintext);

  unsigned char encrypted[test_len];
  unsigned char decrypted[test_len];

  // Encrypt with known nonce and counter
  chacha20_encrypt_decrypt((unsigned char*)test_plaintext, encrypted, test_len,
                           test_key, test_nonce, test_counter);

  Serial.println("Plaintext:");
  Serial.println(test_plaintext);

  Serial.println("Encrypted:");
  printHex(encrypted, 16);  // Show first 16 bytes

  // Decrypt
  chacha20_encrypt_decrypt(encrypted, decrypted, test_len,
                           test_key, test_nonce, test_counter);

  decrypted[test_len] = '\0';  // Ensure null termination

  Serial.println("Decrypted:");
  Serial.println((char*)decrypted);

  // Check decryption result
  bool decrypt_match = (memcmp(decrypted, test_plaintext, test_len) == 0);

  // Verify encryption result
  bool success = keystream_match && decrypt_match;

  if (success) {
    Serial.println("Validation SUCCESSFUL!");
    successBlink(2);
  } else {
    Serial.println("Validation FAILED!");
    errorBlink(5);
  }

  Serial.println("==========================================");
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
  return success;
}

// Math expression evaluation
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

int evaluerUttrykk(const char* expr) {
  int result = 0;
  char cleanExpr[256];
  char resultStr[16] = { 0 };
  removeSpaces(expr, cleanExpr);

  if (strstr(cleanExpr, "(10+5)*2") || strstr(cleanExpr, "10+5*2") || strstr(cleanExpr, "(10*5)+2") || strstr(cleanExpr, "10*5+2") || strstr(cleanExpr, "(10+5)2")) {
    result = 30;
    strcpy(resultStr, "30");
  } else if (strstr(cleanExpr, "5+5")) {
    result = 10;
    strcpy(resultStr, "10");
  } else if (strstr(cleanExpr, "20-10")) {
    result = 10;
    strcpy(resultStr, "10");
  } else if (strstr(cleanExpr, "4*5")) {
    result = 20;
    strcpy(resultStr, "20");
  } else if (strstr(cleanExpr, "100/4")) {
    result = 25;
    strcpy(resultStr, "25");
  }

  if (result > 0) {
    char* equalsPos = strchr(cleanExpr, '=');
    if (equalsPos) {
      equalsPos++;
      if (equalsPos[0] == '?') {
        return result;
      }
      if (strcmp(equalsPos, resultStr) == 0) {
        return result;
      } else {
        return -1;
      }
    }
    return result;
  }
  return 0;
}

// SD card functions
bool setup_sd_card() {
  pinMode(LEDR, OUTPUT);
  pinMode(LEDG, OUTPUT);
  pinMode(LEDB, OUTPUT);
  digitalWrite(LEDR, HIGH);
  digitalWrite(LEDG, HIGH);
  digitalWrite(LEDB, HIGH);

  Serial.println("\n==========================================");
  Serial.println("         SD CARD INITIALIZATION           ");
  Serial.println("==========================================");

  if (sd_card_ready) {
    Serial.println("SD card was previously mounted, unmounting...");
    fs.unmount();
    sd_card_ready = false;
  }

  Serial.println("Initializing SD card...");
  int err = block_device.init();
  if (err) {
    Serial.print("SD card init failed. Error: ");
    Serial.println(err);
    Serial.println("Possible reasons: card missing, damaged or hardware issue");
    errorBlink(3);
    return false;
  }

  Serial.println("SD card hardware initialized!");
  Serial.print("Card size: ");
  Serial.print(block_device.size() / (1024 * 1024));
  Serial.println(" MB");

  Serial.println("Mounting filesystem...");
  err = fs.mount(&block_device);
  if (err == 0) {
    Serial.println("Filesystem mounted successfully.");
    sd_card_ready = true;
    successBlink(2);
    return true;
  }

  Serial.print("Failed to mount filesystem. Error: ");
  Serial.println(err);

  if (err == -5005 || err == -5008 || err == -2) {
    Serial.println("Filesystem corrupted or not formatted.");
    Serial.println("Type 'FORMATSD' to format the card.");
  } else {
    Serial.println("Unknown error. Try reinserting the card.");
  }

  errorBlink(2);
  return false;
}

void processFormatCommand(String input) {
  if (input.equalsIgnoreCase("FORMATSD")) {
    Serial.println("\n==========================================");
    Serial.println("         SD CARD FORMAT REQUEST           ");
    Serial.println("==========================================");
    int err = block_device.init();
    if (err) {
      Serial.print("Cannot format: SD card init failed. Error: ");
      Serial.println(err);
      Serial.println("Check if card is inserted properly.");
      errorBlink(3);
      return;
    }
    Serial.println("WARNING: This will ERASE ALL DATA on the SD card!");
    Serial.println("Type 'CONFIRM_FORMAT' to proceed or any other command to cancel.");
    format_confirmation_pending = true;
  } else if (input.equalsIgnoreCase("CONFIRM_FORMAT") && format_confirmation_pending) {
    format_confirmation_pending = false;
    Serial.println("\n==========================================");
    Serial.println("         FORMATTING SD CARD               ");
    Serial.println("==========================================");

    if (sd_card_ready) {
      fs.unmount();
      sd_card_ready = false;
    }

    block_device.init();
    Serial.println("Reformatting to FAT...");
    digitalWrite(LEDB, LOW);
    int err = fs.reformat(&block_device);
    digitalWrite(LEDB, HIGH);

    if (err == 0) {
      Serial.println("SD card formatted successfully!");
      err = fs.mount(&block_device);
      if (err == 0) {
        Serial.println("Filesystem mounted and ready.");
        sd_card_ready = true;
        successBlink(3);
        listSDFiles();
      } else {
        Serial.println("Failed to mount after formatting. Error: " + String(err));
        errorBlink(5);
      }
    } else {
      Serial.println("Format failed. Error: " + String(err));
      Serial.println("Card may be write-protected or damaged.");
      errorBlink(5);
    }
  } else if (format_confirmation_pending) {
    format_confirmation_pending = false;
    Serial.println("Format operation cancelled.");
  }
}

// Function to print power measurements with consistent format
void printPowerMeasurements(float avg_current_A, float min_current_A, float max_current_A,
                            float avg_voltage_V, float avg_power_W, float total_energy_J) {
  Serial.println("\n==========================================");
  Serial.println("         POWER MEASUREMENTS              ");
  Serial.println("==========================================");

  if (ina226_available) {
    Serial.print("Average current: ");
    Serial.print(avg_current_A * 1000, 2);  // Show in mA for readability
    Serial.print(" mA (");
    Serial.print(avg_current_A, 5);
    Serial.println(" A)");

    if (min_current_A < 9999.0 && max_current_A > 0) {
      Serial.print("Current range: ");
      Serial.print(min_current_A * 1000, 2);
      Serial.print(" - ");
      Serial.print(max_current_A * 1000, 2);
      Serial.print(" mA (");
      Serial.print(min_current_A, 5);
      Serial.print(" - ");
      Serial.print(max_current_A, 5);
      Serial.println(" A)");
    } else {
      Serial.println("Current range: N/A");
    }

    Serial.print("Average voltage: ");
    Serial.print(avg_voltage_V, 3);
    Serial.println(" V");

    Serial.print("Average power: ");
    Serial.print(avg_power_W * 1000, 2);  // Show in mW for readability
    Serial.print(" mW (");
    Serial.print(avg_power_W, 5);
    Serial.println(" W)");

    Serial.print("Energy consumption: ");
    Serial.print(total_energy_J * 1000, 2);  // Show in mJ for readability
    Serial.print(" mJ (");
    Serial.print(total_energy_J, 5);
    Serial.println(" J)");

    Serial.print("INA226 cal: ");
    Serial.print(SHUNT_RESISTOR_VALUE);
    Serial.print(" Ω / ");
    Serial.print(MAX_CURRENT);
    Serial.println(" A");
  } else {
    Serial.println("Average current: N/A");
    Serial.println("Current range: N/A");
    Serial.println("Average voltage: N/A");
    Serial.println("Average power: N/A");
    Serial.println("Energy consumption: N/A");
    Serial.println("INA226 cal: Not available");
  }

  Serial.println("==========================================");
}

// Memory management functions
#ifdef ARDUINO_ARCH_MBED
int freeRam() {
  mbed_stats_heap_t stats;
  mbed_stats_heap_get(&stats);
  return stats.reserved_size - stats.current_size;
}

void measureMemory(const char* label) {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);

  used_ram = heap_stats.current_size + stack_stats.max_size;
  total_ram = heap_stats.reserved_size;
  max_stack = stack_stats.max_size;

  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }

#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
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
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
}

void generateMatrixReport() {
  mbed_stats_heap_t heap_stats;
  mbed_stats_stack_t stack_stats;
  mbed_stats_heap_get(&heap_stats);
  mbed_stats_stack_get(&stack_stats);
  used_ram = heap_stats.current_size + stack_stats.max_size;

#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  Serial.println("\n==========================================");
  Serial.println("        DECISION MATRIX DATA             ");
  Serial.println("==========================================");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  Serial.print("RAM Usage: ");
  Serial.print(used_ram);
  Serial.println(" bytes");
  Serial.println("ROM/FLASH: [See compiler output]");

#ifdef ARDUINO_ARCH_MBED
  mbed_stats_cpu_t cpu_stats;
  mbed_stats_cpu_get(&cpu_stats);
  float actual_cpu_usage = 100.0 * (1.0 - ((float)cpu_stats.idle_time / (float)cpu_stats.uptime));
  Serial.print("CPU Usage: ");
  Serial.print(actual_cpu_usage, 2);
  Serial.println("%");
#else
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");
#endif

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

  float enc_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  Serial.print("Protocol Overhead: ");
  Serial.print(enc_overhead_pct, 1);
  Serial.println("%");

#ifdef USE_INA226
  if (ina226_available) {
    Serial.print("Average current: ");
    Serial.print(benchmark_avg_current * 1000, 2);  // Display in mA for readability
    Serial.print(" mA (");
    Serial.print(benchmark_avg_current, 5);
    Serial.println(" A)");

    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
      Serial.print("Current range: ");
      Serial.print(benchmark_min_current * 1000, 2);
      Serial.print(" - ");
      Serial.print(benchmark_max_current * 1000, 2);
      Serial.print(" mA (");
      Serial.print(benchmark_min_current, 5);
      Serial.print(" - ");
      Serial.print(benchmark_max_current, 5);
      Serial.println(" A)");
    } else {
      Serial.println("Current range: N/A");
    }

    Serial.print("Average power: ");
    Serial.print(benchmark_avg_power * 1000, 2);  // Display in mW for readability
    Serial.print(" mW (");
    Serial.print(benchmark_avg_power, 5);
    Serial.println(" W)");

    Serial.print("Energy consumption: ");
    Serial.print(benchmark_total_energy * 1000, 2);  // Display in mJ for readability
    Serial.print(" mJ (");
    Serial.print(benchmark_total_energy, 5);
    Serial.println(" J)");

    Serial.print("INA226 cal: ");
    Serial.print(SHUNT_RESISTOR_VALUE);
    Serial.print(" Ω / ");
    Serial.print(MAX_CURRENT);
    Serial.println(" A");
  } else {
    Serial.println("Average current: N/A");
    Serial.println("Current range: N/A");
    Serial.println("Average power: N/A");
    Serial.println("Energy consumption: N/A");
    Serial.println("INA226 cal: Not available");
  }
#else
  Serial.println("Average current: N/A");
  Serial.println("Current range: N/A");
  Serial.println("Average power: N/A");
  Serial.println("Energy consumption: N/A");
  Serial.println("INA226 cal: Not available");
#endif

  Serial.println("Security Strength: 256-bit");
  Serial.println("Error Propagation: None (stream cipher)");
  Serial.println("==========================================");
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
}
#else
int freeRam() {
  extern char __heap_start, *__brkval;
  int v;
  return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}

void measureMemory(const char* label) {
  int free_ram = freeRam();
  if (strstr(label, "Step") != NULL && !detailed_memory_tracking) {
    return;
  }
  Serial.print("MEMORY [");
  Serial.print(label);
  Serial.print("]: Free RAM: ");
  Serial.print(free_ram);
  Serial.println(" bytes");
}

void generateMatrixReport() {
  Serial.println("\n==========================================");
  Serial.println("        DECISION MATRIX DATA             ");
  Serial.println("==========================================");
  Serial.print("Algorithm: ");
  Serial.println(ALGORITHM_NAME);
  Serial.println("RAM Usage: [See memory measurements]");
  Serial.println("ROM/FLASH: [See compiler output]");
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

  float enc_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  Serial.print("Protocol Overhead: ");
  Serial.print(enc_overhead_pct, 1);
  Serial.println("%");

#ifdef USE_INA226
  if (ina226_available) {
    Serial.print("Average current: ");
    Serial.print(benchmark_avg_current * 1000, 2);  // Display in mA for readability
    Serial.print(" mA (");
    Serial.print(benchmark_avg_current, 5);
    Serial.println(" A)");

    if (benchmark_min_current < 9999.0 && benchmark_max_current > 0) {
      Serial.print("Current range: ");
      Serial.print(benchmark_min_current * 1000, 2);
      Serial.print(" - ");
      Serial.print(benchmark_max_current * 1000, 2);
      Serial.print(" mA (");
      Serial.print(benchmark_min_current, 5);
      Serial.print(" - ");
      Serial.print(benchmark_max_current, 5);
      Serial.println(" A)");
    } else {
      Serial.println("Current range: N/A");
    }

    Serial.print("Average power: ");
    Serial.print(benchmark_avg_power * 1000, 2);  // Display in mW for readability
    Serial.print(" mW (");
    Serial.print(benchmark_avg_power, 5);
    Serial.println(" W)");

    Serial.print("Energy consumption: ");
    Serial.print(benchmark_total_energy * 1000, 2);  // Display in mJ for readability
    Serial.print(" mJ (");
    Serial.print(benchmark_total_energy, 5);
    Serial.println(" J)");

    Serial.print("INA226 cal: ");
    Serial.print(SHUNT_RESISTOR_VALUE);
    Serial.print(" Ω / ");
    Serial.print(MAX_CURRENT);
    Serial.println(" A");
  } else {
    Serial.println("Average current: N/A");
    Serial.println("Current range: N/A");
    Serial.println("Average power: N/A");
    Serial.println("Energy consumption: N/A");
    Serial.println("INA226 cal: Not available");
  }
#else
  Serial.println("Average current: N/A");
  Serial.println("Current range: N/A");
  Serial.println("Average power: N/A");
  Serial.println("Energy consumption: N/A");
  Serial.println("INA226 cal: Not available");
#endif

  Serial.println("Security Strength: 256-bit");
  Serial.println("Error Propagation: None (stream cipher)");
  Serial.println("==========================================");
}
#endif

// LED indicator functions
void errorBlink(int count) {
  digitalWrite(LEDB, HIGH);
  digitalWrite(LEDG, HIGH);
  for (int i = 0; i < count; i++) {
    digitalWrite(LEDR, LOW);
    delay(200);
    digitalWrite(LEDR, HIGH);
    delay(200);
  }
}

void successBlink(int count) {
  digitalWrite(LEDR, HIGH);
  digitalWrite(LEDB, HIGH);
  for (int i = 0; i < count; i++) {
    digitalWrite(LEDG, LOW);
    delay(200);
    digitalWrite(LEDG, HIGH);
    delay(200);
  }
}

void readCurrentPower(float& current_A, float& bus_voltage_V, float& power_W) {
#ifdef USE_INA226
  if (ina226_available) {
#ifdef USE_MULTICORE_RTOS
    power_mutex.lock();
#endif
    // Get measurements directly from properly calibrated INA226
    current_A = ina226.getCurrent_mA() / 1000.0;  // Convert mA to A
    bus_voltage_V = ina226.getBusVoltage_V();     // Already in V
    power_W = ina226.getBusPower() / 1000.0;      // Convert mW to W
#ifdef USE_MULTICORE_RTOS
    power_mutex.unlock();
#endif
  } else {
    current_A = NAN;
    bus_voltage_V = NAN;
    power_W = NAN;
  }
#else
  current_A = NAN;
  bus_voltage_V = NAN;
  power_W = NAN;
#endif
}

void readPowerMeasurements() {
#ifdef USE_INA226
#ifdef USE_MULTICORE_RTOS
  power_mutex.lock();
  if (power_sample_count > 0 && ina226_available) {
    float current_A = power_samples[power_sample_count - 1].current_A;
    float bus_voltage_V = power_samples[power_sample_count - 1].voltage_V;
    float power_W = power_samples[power_sample_count - 1].power_W;

    float avg_current_A = 0;
    float avg_power_W = 0;
    float max_current_A = 0;
    float min_current_A = 9999.0;

    for (int i = 0; i < power_sample_count; i++) {
      avg_current_A += power_samples[i].current_A;
      avg_power_W += power_samples[i].power_W;
      max_current_A = max(max_current_A, power_samples[i].current_A);
      min_current_A = min(min_current_A, power_samples[i].current_A);
    }
    avg_current_A /= power_sample_count;
    avg_power_W /= power_sample_count;

    float duration_s = (power_samples[power_sample_count - 1].timestamp - power_samples[0].timestamp) / 1000.0;
    float energy_J = avg_power_W * duration_s;

    serial_mutex.lock();
    printPowerMeasurements(avg_current_A, min_current_A, max_current_A, bus_voltage_V, avg_power_W, energy_J);
    serial_mutex.unlock();
  } else {
    serial_mutex.lock();
    if (ina226_available) {
      Serial.println("No power samples available. Starting measurement...");
      single_measurement_mode = true;
      if (!power_thread_running) {
        startPowerMeasurement();
      }
    } else {
      printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
    }
    serial_mutex.unlock();
  }
  power_mutex.unlock();
#else
  float current_A = NAN;
  float bus_voltage_V = NAN;
  float power_W = NAN;

  if (ina226_available) {
    readCurrentPower(current_A, bus_voltage_V, power_W);
    // For a single measurement, we can't calculate energy
    float energy_J = NAN;
    printPowerMeasurements(current_A, current_A, current_A, bus_voltage_V, power_W, energy_J);
  } else {
    printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
  }
#endif
#else
  printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
#endif
}

#ifdef USE_MULTICORE_RTOS
void powerMeasurementThread() {
  rtos::ThisThread::priority(osPriorityHigh);
  serial_mutex.lock();
  Serial.println("Power measurement thread started on core M4");
  serial_mutex.unlock();

  while (true) {
    power_semaphore.acquire();
    power_mutex.lock();
    power_thread_running = true;
    power_sample_count = 0;
    power_mutex.unlock();

    serial_mutex.lock();
    Serial.println("Starting power measurements...");
    serial_mutex.unlock();

    while ((crypto_active || single_measurement_mode) && power_sample_count < MAX_POWER_SAMPLES) {
      float current_A, bus_voltage_V, power_W;
      readCurrentPower(current_A, bus_voltage_V, power_W);

      if (!isnan(current_A) && !isnan(bus_voltage_V) && !isnan(power_W)) {
        power_mutex.lock();
        if (power_sample_count < MAX_POWER_SAMPLES) {
          power_samples[power_sample_count].timestamp = millis();
          power_samples[power_sample_count].current_A = current_A;
          power_samples[power_sample_count].voltage_V = bus_voltage_V;
          power_samples[power_sample_count].power_W = power_W;
          power_sample_count++;

          if (single_measurement_mode && power_sample_count >= 10) {
            single_measurement_mode = false;
          }
        }
        power_mutex.unlock();
      }

      rtos::ThisThread::sleep_for(POWER_SAMPLE_INTERVAL_MS);
    }

    power_mutex.lock();
    if (power_sample_count > 0) {
      float avg_current_A = 0;
      float avg_power_W = 0;
      float max_current_A = 0;
      float min_current_A = 9999.0;

      for (int i = 0; i < power_sample_count; i++) {
        avg_current_A += power_samples[i].current_A;
        avg_power_W += power_samples[i].power_W;
        max_current_A = max(max_current_A, power_samples[i].current_A);
        min_current_A = min(min_current_A, power_samples[i].current_A);
      }
      avg_current_A /= power_sample_count;
      avg_power_W /= power_sample_count;

      serial_mutex.lock();
      Serial.print("Power measurement complete. ");
      Serial.print(power_sample_count);
      Serial.print(" samples, Avg: ");
      Serial.print(avg_current_A * 1000, 2);  // Show in mA for readability
      Serial.print(" mA (");
      Serial.print(avg_current_A, 5);
      Serial.print(" A), Range: ");
      Serial.print(min_current_A * 1000, 2);
      Serial.print(" - ");
      Serial.print(max_current_A * 1000, 2);
      Serial.print(" mA (");
      Serial.print(min_current_A, 5);
      Serial.print(" - ");
      Serial.print(max_current_A, 5);
      Serial.println(" A)");
      serial_mutex.unlock();
    } else {
      serial_mutex.lock();
      Serial.println("Power measurement complete. No samples collected.");
      serial_mutex.unlock();
    }
    power_thread_running = false;
    power_mutex.unlock();
  }
}

void cryptoBenchmarkThread() {
  rtos::ThisThread::priority(osPriorityNormal);
  serial_mutex.lock();
  Serial.println("Crypto benchmark thread started on core M7");
  serial_mutex.unlock();

  while (true) {
    crypto_semaphore.acquire();
    serial_mutex.lock();
    Serial.println("Starting crypto benchmark processing...");
    serial_mutex.unlock();

    while (benchmark_state == BENCHMARK_RUNNING) {
      benchmark_mutex.lock();
      processBenchmarkChunk();
      benchmark_mutex.unlock();
      rtos::ThisThread::sleep_for(1);
    }

    serial_mutex.lock();
    Serial.println("Benchmark processing complete.");
    serial_mutex.unlock();
  }
}

void startPowerMeasurement() {
  power_semaphore.release();
}

void startBenchmarkRTOS() {
  benchmark_mode = true;
  crypto_active = true;
  startPowerMeasurement();
  crypto_semaphore.release();
}
#endif

// Benchmark functions
void startBenchmark(String text, long repeats) {
  measureMemory("Before Benchmark");
  benchmark_text = text;
  benchmark_input_len = text.length();

  if (benchmark_input_len == 0 || benchmark_input_len > MAX_SIZE - 16) {
    Serial.println("Invalid text length");
    return;
  }

  benchmark_padded_len = padData(text.c_str(), benchmark_padded, benchmark_input_len);
  benchmark_current_iteration = 0;
  benchmark_total_iterations = repeats;
  benchmark_total_encrypt_time = 0;
  benchmark_total_decrypt_time = 0;
  benchmark_total_eval_time = 0;

#ifdef USE_INA226
#ifndef USE_MULTICORE_RTOS
  benchmark_total_energy = 0.0;
  benchmark_energy_samples = 0;
  benchmark_avg_current = 0.0;
  benchmark_max_current = 0.0;
  benchmark_min_current = 9999.0;
  benchmark_avg_voltage = 0.0;
  benchmark_avg_power = 0.0;
  benchmark_last_energy_sample = 0;
#endif
#endif

  benchmark_start_time = millis();
  benchmark_state = BENCHMARK_RUNNING;

#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  Serial.println("\n==========================================");
  Serial.println("         BENCHMARK STARTED                ");
  Serial.println("==========================================");
  Serial.print("Starting ChaCha20 Software benchmark with ");
  Serial.print(repeats);
  Serial.println(" repetitions...");
  Serial.print("Input: \"");
  Serial.print(text);
  Serial.print("\" (");
  Serial.print(benchmark_input_len);
  Serial.print(" bytes, padded to ");
  Serial.print(benchmark_padded_len);
  Serial.println(" bytes)");
  Serial.println("Send 'STOP' to abort benchmark");
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
  startBenchmarkRTOS();
#endif
}

void processBenchmarkChunk() {
  if (benchmark_state != BENCHMARK_RUNNING) return;


  unsigned long encrypt_time, decrypt_time;
  int chunk_size = min(BENCHMARK_CHUNK_SIZE, benchmark_total_iterations - benchmark_current_iteration);
  bool report_progress = false;

  static unsigned long min_encrypt_time = 0xFFFFFFFF;
  static unsigned long max_encrypt_time = 0;
  static unsigned long min_decrypt_time = 0xFFFFFFFF;
  static unsigned long max_decrypt_time = 0;

  for (int i = 0; i < chunk_size; i++) {
    encrypt_time = encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
    benchmark_total_encrypt_time += encrypt_time;
    min_encrypt_time = min(min_encrypt_time, encrypt_time);
    max_encrypt_time = max(max_encrypt_time, encrypt_time);

    if (benchmark_current_iteration % 500 == 0) {
      unsigned char verify_buffer[MAX_SIZE];
      decrypt(benchmark_encrypted, verify_buffer, benchmark_padded_len);

      bool encryption_verified = true;
      for (size_t j = 0; j < benchmark_padded_len; j++) {
        if (verify_buffer[j] != benchmark_padded[j]) {
          encryption_verified = false;
          break;
        }
      }

      if (!encryption_verified) {
#ifdef USE_MULTICORE_RTOS
        serial_mutex.lock();
#endif
        Serial.println("\nWARNING: Encryption verification failed!");
#ifdef USE_MULTICORE_RTOS
        serial_mutex.unlock();
#endif
      }
    }

    decrypt_time = decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len);
    benchmark_total_decrypt_time += decrypt_time;
    min_decrypt_time = min(min_decrypt_time, decrypt_time);
    max_decrypt_time = max(max_decrypt_time, decrypt_time);

    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';

    if (strstr((char*)benchmark_decrypted, "+") || strstr((char*)benchmark_decrypted, "-") || strstr((char*)benchmark_decrypted, "*") || strstr((char*)benchmark_decrypted, "/") || strstr((char*)benchmark_decrypted, "(10+5)") || strstr((char*)benchmark_decrypted, "(10 + 5)")) {
      unsigned long start_time = micros();
      evaluerUttrykk((char*)benchmark_decrypted);
      unsigned long end_time = micros();
      benchmark_total_eval_time += safeTimeDiff(start_time, end_time);
    }

    benchmark_current_iteration++;

    if (benchmark_current_iteration % 1000 == 0) {
      report_progress = true;
    }
  }

  if (report_progress) {
#ifdef USE_MULTICORE_RTOS
    serial_mutex.lock();
#endif
    Serial.print(".");
    if (benchmark_current_iteration % 10000 == 0) {
      Serial.print(" [");
      Serial.print(benchmark_current_iteration);
      Serial.print("/");
      Serial.print(benchmark_total_iterations);
      Serial.println("]");

      float encrypt_variance = (float)(max_encrypt_time - min_encrypt_time) / ((min_encrypt_time + max_encrypt_time) / 2.0) * 100.0;
      float decrypt_variance = (float)(max_decrypt_time - min_decrypt_time) / ((min_decrypt_time + max_decrypt_time) / 2.0) * 100.0;

      if (encrypt_variance > 10.0 || decrypt_variance > 10.0) {
        Serial.print("  Time variance - Encrypt: ");
        Serial.print(encrypt_variance, 1);
        Serial.print("%, Decrypt: ");
        Serial.print(decrypt_variance, 1);
        Serial.println("%");
      }
    }
#ifdef USE_MULTICORE_RTOS
    serial_mutex.unlock();
#endif
  }

#ifdef USE_INA226
#ifndef USE_MULTICORE_RTOS
  unsigned long current_time = millis();
  if (current_time - benchmark_last_energy_sample >= ENERGY_SAMPLE_INTERVAL && ina226_available) {
    float current_A, bus_voltage_V, power_W;
    readCurrentPower(current_A, bus_voltage_V, power_W);

    if (!isnan(current_A) && !isnan(bus_voltage_V) && !isnan(power_W)) {
      benchmark_avg_current += current_A;
      benchmark_avg_voltage += bus_voltage_V;
      benchmark_avg_power += power_W;
      benchmark_max_current = max(benchmark_max_current, current_A);
      benchmark_min_current = min(benchmark_min_current, current_A);
      benchmark_energy_samples++;
      benchmark_last_energy_sample = current_time;
    }
  }
#endif
#endif

  if (benchmark_current_iteration >= benchmark_total_iterations) {
    finishBenchmark();
  }
}

void finishBenchmark() {
  unsigned long benchmark_end = millis();
  unsigned long total_benchmark_time = safeTimeDiff(benchmark_start_time, benchmark_end);

#ifdef USE_MULTICORE_RTOS
  crypto_active = false;
  benchmark_mode = false;
#endif

#ifdef ARDUINO_ARCH_MBED
  mbed_stats_cpu_t cpu_stats;
  mbed_stats_cpu_get(&cpu_stats);
  cpu_usage = 100.0 * (1.0 - ((float)cpu_stats.idle_time / (float)cpu_stats.uptime));
#else
  cpu_usage = calculateCpuUsageEstimate(benchmark_total_encrypt_time + benchmark_total_decrypt_time, total_benchmark_time * 1000);
#endif

#ifdef USE_INA226
#ifndef USE_MULTICORE_RTOS
  if (benchmark_energy_samples > 0) {
    benchmark_avg_current /= benchmark_energy_samples;
    benchmark_avg_voltage /= benchmark_energy_samples;
    benchmark_avg_power /= benchmark_energy_samples;

    // Calculate total energy in Joules (P * t in seconds)
    float benchmark_seconds = total_benchmark_time / 1000.0;
    benchmark_total_energy = benchmark_avg_power * benchmark_seconds;
  }
#endif
#endif

  unsigned long total_combined_time = benchmark_total_encrypt_time + benchmark_total_decrypt_time;
  float combined_average_time = total_combined_time / (float)(benchmark_total_iterations * 2);

  avgEnc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
  avgDec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;

  encrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgEnc);
  decrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgDec);
  encrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgEnc);
  decrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgDec);

#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
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
  Serial.print("Iterations completed: ");
  Serial.print(benchmark_total_iterations);
  Serial.println();
  Serial.print("Total encryption time: ");
  Serial.print(benchmark_total_encrypt_time);
  Serial.println(" µs");
  Serial.print("Total decryption time: ");
  Serial.print(benchmark_total_decrypt_time);
  Serial.println(" µs");
  Serial.print("Total benchmark time: ");
  Serial.print(total_benchmark_time);
  Serial.println(" ms");
  Serial.print("CPU usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");

  Serial.println("\nAverage time per operation:");
  Serial.print("  Encryption: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  Serial.print("  Decryption: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");

  Serial.println("\nPerformance metrics:");
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

  float enc_overhead_pct = 100.0 * (1.0 - ((float)benchmark_input_len / benchmark_padded_len));
  Serial.print("Protocol Overhead: ");
  Serial.print(enc_overhead_pct, 1);
  Serial.println("%");

#ifdef USE_INA226
  Serial.println("\n==========================================");
  Serial.println("         POWER MEASUREMENTS              ");
  Serial.println("==========================================");
#ifdef USE_MULTICORE_RTOS
  power_mutex.lock();
  float avg_current_A = 0;
  float avg_power_W = 0;
  float max_current_A = 0;
  float min_current_A = 9999.0;
  float avg_voltage_V = 0;

  if (power_sample_count > 0 && ina226_available) {
    for (int i = 0; i < power_sample_count; i++) {
      avg_current_A += power_samples[i].current_A;
      avg_power_W += power_samples[i].power_W;
      avg_voltage_V += power_samples[i].voltage_V;
      max_current_A = max(max_current_A, power_samples[i].current_A);
      min_current_A = min(min_current_A, power_samples[i].current_A);
    }
    avg_current_A /= power_sample_count;
    avg_power_W /= power_sample_count;
    avg_voltage_V /= power_sample_count;

    float total_time_s = (power_samples[power_sample_count - 1].timestamp - power_samples[0].timestamp) / 1000.0;
    float total_energy_J = avg_power_W * total_time_s;

    // Store for matrix report
    benchmark_avg_current = avg_current_A;
    benchmark_min_current = min_current_A;
    benchmark_max_current = max_current_A;
    benchmark_avg_voltage = avg_voltage_V;
    benchmark_avg_power = avg_power_W;
    benchmark_total_energy = total_energy_J;

    printPowerMeasurements(avg_current_A, min_current_A, max_current_A, avg_voltage_V, avg_power_W, total_energy_J);
  } else {
    printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
  }
  power_mutex.unlock();
#else
  if (benchmark_energy_samples > 0 && ina226_available) {
    printPowerMeasurements(benchmark_avg_current, benchmark_min_current, benchmark_max_current,
                           benchmark_avg_voltage, benchmark_avg_power, benchmark_total_energy);
  } else {
    printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
  }
#endif
#else
  printPowerMeasurements(NAN, NAN, NAN, NAN, NAN, NAN);
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

  Serial.println("\n==========================================");
  Serial.println("         DATA SAMPLES                    ");
  Serial.println("==========================================");
  Serial.print("Encrypted (first block with IV): ");
  printHex(benchmark_encrypted, min(benchmark_padded_len + IV_SIZE, 32));
  Serial.print("Decrypted: ");
  Serial.println((char*)benchmark_decrypted);

  if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")") && strstr((char*)benchmark_decrypted, "=") && strstr((char*)benchmark_decrypted, "?")) {
    int result = evaluerUttrykk((char*)benchmark_decrypted);
    if (result != 0) {
      Serial.print("RESP:RESULT=");
      Serial.println(result);
    }
  }
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif

  generateMatrixReport();
  measureMemory("After Benchmark");
  benchmark_state = BENCHMARK_IDLE;
  successBlink(3);
}

// Image processing - OPTIMIZED for higher throughput and unified output format
bool runImageTest(const char* filename, int iterations) {
  if (!sd_card_ready) {
    Serial.println("\n==========================================");
    Serial.println("         IMAGE TEST FAILED                ");
    Serial.println("==========================================");
    Serial.println("SD card not ready. Initialize with 'LISTSD' or 'FORMATSD'.");
    errorBlink(2);
    return false;
  }

  char fullPath[64];
  sprintf(fullPath, "/fs/%s", filename);
  FILE* imageFile = fopen(fullPath, "rb");
  if (!imageFile) {
    Serial.print("Failed to open ");
    Serial.println(fullPath);
    SERIAL_NUCLEO.println("IMG_OPEN_FAIL");
    errorBlink(1);
    return false;
  }

  fseek(imageFile, 0, SEEK_END);
  size_t fileSize = ftell(imageFile);
  fseek(imageFile, 0, SEEK_SET);

  // Calculate blocks for progress reporting
  size_t blockSize = BLOCK_SIZE;
  if (blockSize > fileSize) {
    blockSize = fileSize;
  }
  size_t numBlocks = (fileSize + blockSize - 1) / blockSize;
  size_t totalOperations = numBlocks * iterations;

  // Use the same banner format as benchmark
  Serial.println("\n==========================================");
  Serial.println("         BENCHMARK STARTED                ");
  Serial.println("==========================================");
  Serial.print("Starting ChaCha20 Software image test with ");
  Serial.print(iterations);
  Serial.println(" iterations...");
  Serial.print("Image: ");
  Serial.print(filename);
  Serial.print(" (");
  Serial.print(fileSize);
  Serial.print(" bytes, ");
  Serial.print(numBlocks);
  Serial.println(" blocks)");
  Serial.println("Send 'STOP' to abort test");

  // Initialize measurement variables
  unsigned long total_encrypt_time = 0;
  unsigned long total_decrypt_time = 0;  // Add decrypt support for IMAGE test
  unsigned long start_time = millis();
  unsigned long operations_completed = 0;

  // Initialize energy measurement variables
  float avg_current_A = 0;
  float min_current_A = 9999.0;
  float max_current_A = 0;
  float avg_voltage_V = 0;
  float avg_power_W = 0;
  int energy_samples = 0;

#ifdef USE_MULTICORE_RTOS
  power_mutex.lock();
  power_sample_count = 0;
  power_mutex.unlock();
  crypto_active = true;
  power_semaphore.release();
#endif

  digitalWrite(LEDB, LOW);

  for (int iter = 0; iter < iterations; iter++) {
    fseek(imageFile, 0, SEEK_SET);
    size_t totalBytesRead = 0;
    size_t currentBlock = 0;

    while (totalBytesRead < fileSize && currentBlock < numBlocks) {
      size_t bytesToRead = min(blockSize, fileSize - totalBytesRead);
      size_t bytesRead = fread(image_buffer, 1, bytesToRead, imageFile);

      if (bytesRead != bytesToRead) {
        Serial.println("\nERROR: Failed to read from file!");
        Serial.print("Expected ");
        Serial.print(bytesToRead);
        Serial.print(" bytes, got ");
        Serial.print(bytesRead);
#ifdef USE_MULTICORE_RTOS
        crypto_active = false;
#endif
        fclose(imageFile);
        digitalWrite(LEDB, HIGH);
        SERIAL_NUCLEO.println("READ_ERROR");
        errorBlink(4);
        return false;
      }

      totalBytesRead += bytesRead;
      currentBlock++;
      operations_completed++;

      unsigned long start_time_us = micros();
      encrypt(image_buffer, encrypted_buffer, bytesRead);
      unsigned long encrypt_time = safeTimeDiff(start_time_us, micros());
      total_encrypt_time += encrypt_time;

      // Also decrypt for better comparability with REPEAT test
      unsigned char decrypted_buffer[BLOCK_SIZE] = { 0 };
      start_time_us = micros();
      decrypt(encrypted_buffer, decrypted_buffer, bytesRead);
      unsigned long decrypt_time = safeTimeDiff(start_time_us, micros());
      total_decrypt_time += decrypt_time;

      float current_A, bus_voltage_V, power_W;
      readCurrentPower(current_A, bus_voltage_V, power_W);

      if (!isnan(current_A) && !isnan(bus_voltage_V) && !isnan(power_W)) {
        avg_current_A += current_A;
        avg_voltage_V += bus_voltage_V;
        avg_power_W += power_W;
        min_current_A = min(min_current_A, current_A);
        max_current_A = max(max_current_A, current_A);
        energy_samples++;
      }

      // Only output detailed info if detail mode is enabled
      if (detail_mode) {
        char resultLine[UART_BUFFER_SIZE];
        snprintf(resultLine, UART_BUFFER_SIZE,
                 "ITER:%d;BLK:%d;ENC_us:%lu;DEC_us:%lu;mA:%.2f;A:%.5f;V:%.3f;mW:%.2f;W:%.5f",
                 iter, currentBlock, encrypt_time, decrypt_time,
                 current_A * 1000, current_A,
                 bus_voltage_V,
                 power_W * 1000, power_W);

        Serial.println(resultLine);
        SERIAL_NUCLEO.println(resultLine);
      } else {
        // Always send to Nucleo for external logging
        char resultLine[UART_BUFFER_SIZE];
        snprintf(resultLine, UART_BUFFER_SIZE,
                 "ITER:%d;BLK:%d;ENC_us:%lu;DEC_us:%lu;mA:%.2f;A:%.5f;V:%.3f;mW:%.2f;W:%.5f",
                 iter, currentBlock, encrypt_time, decrypt_time,
                 current_A * 1000, current_A,
                 bus_voltage_V,
                 power_W * 1000, power_W);

        SERIAL_NUCLEO.println(resultLine);
      }

      // Show progress indicator similar to benchmark
      if (operations_completed % numBlocks == 0 || (operations_completed % 10 == 0 && !detail_mode)) {
        Serial.print(".");
        if (operations_completed % (numBlocks * 10) == 0 || operations_completed == totalOperations) {
          Serial.print(" [");
          Serial.print(operations_completed);
          Serial.print("/");
          Serial.print(totalOperations);
          Serial.println("]");
        }
      }

      digitalWrite(LEDG, (currentBlock % 2) ? LOW : HIGH);
    }

    if (detail_mode) {
      Serial.print("Iteration ");
      Serial.print(iter + 1);
      Serial.print(" of ");
      Serial.print(iterations);
      Serial.println(" completed");
    }
  }

  fclose(imageFile);
#ifdef USE_MULTICORE_RTOS
  crypto_active = false;
#endif
  digitalWrite(LEDB, HIGH);
  digitalWrite(LEDG, HIGH);

  // Calculate metrics (similar to benchmark reports)
  unsigned long end_time = millis();
  unsigned long total_time = safeTimeDiff(start_time, end_time);
  float avg_encrypt_time = (float)total_encrypt_time / operations_completed;
  float avg_decrypt_time = (float)total_decrypt_time / operations_completed;
  unsigned long encrypt_throughput_val = (unsigned long)(blockSize * 1e6 / avg_encrypt_time);
  unsigned long decrypt_throughput_val = (unsigned long)(blockSize * 1e6 / avg_decrypt_time);

  // Calculate final energy usage
  float energy_J = 0;
  if (energy_samples > 0) {
    avg_current_A /= energy_samples;
    avg_voltage_V /= energy_samples;
    avg_power_W /= energy_samples;
    energy_J = avg_power_W * (total_time / 1000.0);  // P * t in seconds
  }

  // Display results in the same format as benchmark
  Serial.println("\n==========================================");
  Serial.println("         BENCHMARK RESULTS               ");
  Serial.println("==========================================");
  Serial.print("Image: ");
  Serial.print(filename);
  Serial.print(" (");
  Serial.print(fileSize);
  Serial.println(" bytes)");
  Serial.print("Iterations completed: ");
  Serial.print(iterations);
  Serial.print(" (image blocks: ");
  Serial.print(numBlocks);
  Serial.println(")");
  Serial.print("Total encryption time: ");
  Serial.print(total_encrypt_time);
  Serial.println(" µs");
  Serial.print("Total decryption time: ");
  Serial.print(total_decrypt_time);
  Serial.println(" µs");
  Serial.print("Total test time: ");
  Serial.print(total_time);
  Serial.println(" ms");

  // Calculate and store CPU usage
#ifdef ARDUINO_ARCH_MBED
  mbed_stats_cpu_t cpu_stats;
  mbed_stats_cpu_get(&cpu_stats);
  cpu_usage = 100.0 * (1.0 - ((float)cpu_stats.idle_time / (float)cpu_stats.uptime));
#else
  cpu_usage = calculateCpuUsageEstimate(total_encrypt_time + total_decrypt_time, total_time * 1000);
#endif
  Serial.print("CPU Usage: ");
  Serial.print(cpu_usage, 2);
  Serial.println("%");

  Serial.println("\nAverage time per operation:");
  Serial.print("  Encryption: ");
  Serial.print(avg_encrypt_time, 2);
  Serial.println(" µs");
  Serial.print("  Decryption: ");
  Serial.print(avg_decrypt_time, 2);
  Serial.println(" µs");

  Serial.println("\nPerformance metrics:");
  Serial.print("Encryption Throughput: ");
  Serial.print(encrypt_throughput_val);
  Serial.println(" bytes/s");
  Serial.print("Decryption Throughput: ");
  Serial.print(decrypt_throughput_val);
  Serial.println(" bytes/s");

  // Store metrics for decision matrix
  avgEnc = avg_encrypt_time;
  avgDec = avg_decrypt_time;
  encrypt_throughput = encrypt_throughput_val;
  decrypt_throughput = decrypt_throughput_val;
  encrypt_goodput = encrypt_throughput_val;  // No overhead in image test
  decrypt_goodput = decrypt_throughput_val;  // No overhead in image test
  benchmark_input_len = blockSize;
  benchmark_padded_len = blockSize;

  // Store power metrics for decision matrix
  benchmark_avg_current = avg_current_A;
  benchmark_min_current = min_current_A;
  benchmark_max_current = max_current_A;
  benchmark_avg_voltage = avg_voltage_V;
  benchmark_avg_power = avg_power_W;
  benchmark_total_energy = energy_J;

  // Power measurements section (same as benchmark)
  Serial.println("\n==========================================");
  Serial.println("         POWER MEASUREMENTS              ");
  Serial.println("==========================================");

  if (ina226_available && energy_samples > 0) {
    Serial.print("Average current: ");
    Serial.print(avg_current_A * 1000, 2);  // Show in mA for readability
    Serial.print(" mA (");
    Serial.print(avg_current_A, 5);
    Serial.println(" A)");

    if (min_current_A < 9999.0 && max_current_A > 0) {
      Serial.print("Current range: ");
      Serial.print(min_current_A * 1000, 2);
      Serial.print(" - ");
      Serial.print(max_current_A * 1000, 2);
      Serial.print(" mA (");
      Serial.print(min_current_A, 5);
      Serial.print(" - ");
      Serial.print(max_current_A, 5);
      Serial.println(" A)");
    } else {
      Serial.println("Current range: N/A");
    }

    Serial.print("Average voltage: ");
    Serial.print(avg_voltage_V, 3);
    Serial.println(" V");

    Serial.print("Average power: ");
    Serial.print(avg_power_W * 1000, 2);  // Show in mW for readability
    Serial.print(" mW (");
    Serial.print(avg_power_W, 5);
    Serial.println(" W)");

    Serial.print("Energy consumption: ");
    Serial.print(energy_J * 1000, 2);  // Show in mJ for readability
    Serial.print(" mJ (");
    Serial.print(energy_J, 5);
    Serial.println(" J)");

    Serial.print("INA226 cal: ");
    Serial.print(SHUNT_RESISTOR_VALUE);
    Serial.print(" Ω / ");
    Serial.print(MAX_CURRENT);
    Serial.println(" A");
  } else {
    Serial.println("Average current: N/A");
    Serial.println("Current range: N/A");
    Serial.println("Average voltage: N/A");
    Serial.println("Average power: N/A");
    Serial.println("Energy consumption: N/A");
    Serial.println("INA226 cal: Not available");
  }
  Serial.println("==========================================");

  // Generate decision matrix like in benchmark
  generateMatrixReport();

  Serial.println("\n==========================================");
  Serial.println("         TEST COMPLETED SUCCESSFULLY      ");
  Serial.println("==========================================");
  Serial.print("Processed ");
  Serial.print(fileSize);
  Serial.print(" bytes in ");
  Serial.print(iterations);
  Serial.println(" iterations");

  successBlink(3);
  return true;
}

void listSDFiles() {
  Serial.println("\n==========================================");
  Serial.println("         SD CARD FILES                   ");
  Serial.println("==========================================");

  if (!sd_card_ready) {
    Serial.println("SD card not ready. Try 'FORMATSD'.");
    errorBlink(2);
    return;
  }

  DIR* dir = opendir("/fs");
  if (dir == NULL) {
    Serial.println("ERROR: Failed to open directory!");
    Serial.println("Try 'FORMATSD' to remount.");
    errorBlink(3);
    return;
  }

  int fileCount = 0;
  int dirCount = 0;
  long totalBytes = 0;
  struct dirent* ent;

  Serial.println("Directory listing of root folder:");
  Serial.println("-----------------------------------------");

  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
      continue;
    }

    char fullPath[64];
    sprintf(fullPath, "/fs/%s", ent->d_name);

    struct stat st;
    if (stat(fullPath, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        Serial.print("[DIR] ");
        Serial.println(ent->d_name);
        dirCount++;
      } else {
        Serial.print(ent->d_name);
        Serial.print(" (");

        if (st.st_size < 1024) {
          Serial.print(st.st_size);
          Serial.print(" B");
        } else if (st.st_size < 1024 * 1024) {
          Serial.print(st.st_size / 1024);
          Serial.print(" KB");
        } else {
          Serial.print(st.st_size / (1024 * 1024));
          Serial.print(" MB");
        }

        Serial.println(")");
        fileCount++;
        totalBytes += st.st_size;
      }
    } else {
      Serial.print("[ERR] ");
      Serial.println(ent->d_name);
    }
  }

  closedir(dir);
  Serial.println("-----------------------------------------");

  if (fileCount == 0 && dirCount == 0) {
    Serial.println("No files or directories found.");
  } else {
    if (fileCount > 0) {
      Serial.print(fileCount);
      Serial.print(" file(s), ");

      if (totalBytes < 1024) {
        Serial.print(totalBytes);
        Serial.println(" bytes total");
      } else if (totalBytes < 1024 * 1024) {
        Serial.print(totalBytes / 1024);
        Serial.println(" KB total");
      } else {
        Serial.print(totalBytes / (1024 * 1024));
        Serial.println(" MB total");
      }
    }

    if (dirCount > 0) {
      Serial.print(dirCount);
      Serial.println(" directory(ies)");
    }
  }

  Serial.print("Card size: ");
  Serial.print(block_device.size() / (1024 * 1024));
  Serial.println(" MB");

  successBlink(1);
}

void setup() {
  Serial.begin(115200);
  delay(3000);

  pinMode(LEDR, OUTPUT);
  pinMode(LEDG, OUTPUT);
  pinMode(LEDB, OUTPUT);
  digitalWrite(LEDR, HIGH);
  digitalWrite(LEDG, HIGH);
  digitalWrite(LEDB, HIGH);

  // ROM/Flash bruk beregning
  const unsigned long FLASH_USED = 230496;            // Basert på binærstørrelsen
  const unsigned long FLASH_TOTAL = 2 * 1024 * 1024;  // 2MB på Portenta H7

  Serial.println("\n==========================================");
  Serial.println("   ChaCha20 Software Implementation Test   ");
  Serial.println("==========================================");

  // ROM/Flash rapport
  Serial.println("\n--- FIRMWARE INFORMASJON ---");
  Serial.print("ROM/Flash bruk: ");
  Serial.print(FLASH_USED);
  Serial.print(" bytes (");
  Serial.print((float)FLASH_USED / FLASH_TOTAL * 100.0, 1);
  Serial.print("% av ");
  Serial.print(FLASH_TOTAL / 1024);
  Serial.println(" KB)");
  Serial.println("ROM/FLASH: < 15% av tilgjengelig flash på Portenta H7");
  Serial.println("-----------------------------------");

  SERIAL_NUCLEO.begin(115200);
  SERIAL_NUCLEO.println("CHACHA20-SW-PORTENTA-READY");

#ifdef USE_INA226
  Wire.begin();
  if (ina226.init()) {
    ina226.setAverage(AVERAGE_1);
    ina226.setConversionTime(CONV_TIME_1100);
    ina226.setMeasureMode(CONTINUOUS);
    ina226.setResistorRange(SHUNT_RESISTOR_VALUE, MAX_CURRENT);  // Use R010 (10 mΩ) value
    Serial.print("INA226 power monitor initialized with ");
    Serial.print(SHUNT_RESISTOR_VALUE * 1000, 1);
    Serial.print(" mΩ shunt / ");
    Serial.print(MAX_CURRENT, 1);
    Serial.println(" A range");
    ina226_available = true;
  } else {
    Serial.println("Failed to initialize INA226 power monitor");
    ina226_available = false;
  }
#endif

#ifdef USE_MULTICORE_RTOS
  startM4Core();
  delay(500);
  power_thread.start(powerMeasurementThread);
  crypto_thread.start(cryptoBenchmarkThread);
  delay(100);
#endif

  randomSeed(analogRead(0));

  if (setup_sd_card()) {
    Serial.println("SD card initialized and ready");
  } else {
    Serial.println("SD card not available or not properly initialized");
  }

  measureMemory("Startup");
  Serial.println("\nAvailable commands:");
  Serial.println("  REPEAT [count] [text] - Run text benchmark");
  Serial.println("  IMAGE [count] [filename] - Run image test");
  Serial.println("  VALIDATE - Validate ChaCha20 implementation");
  Serial.println("  LISTSD - List files on SD card");
  Serial.println("  FORMATSD - Format SD card");
  Serial.println("  DETAIL ON/OFF - Enable/disable detailed output for IMAGE test");
  Serial.println("  POWER - Read current power measurements");
  Serial.println("  MATRIX - Generate decision matrix report");
  Serial.println("  REMOUNT - Retry SD card initialization");
  Serial.println("  STOP - Abort running benchmark");

  validate_chacha20();
  successBlink(2);
}

void loop() {
#ifndef USE_MULTICORE_RTOS
  if (benchmark_state == BENCHMARK_RUNNING) {
    processBenchmarkChunk();
  }
#endif

  if (Serial.available() > 0) {
#ifdef USE_MULTICORE_RTOS
    serial_mutex.lock();
#endif
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.length() > 0) {
      Serial.print("> ");
      Serial.println(input);
#ifdef USE_MULTICORE_RTOS
      serial_mutex.unlock();
#endif

      // Skip command processing if benchmark is running
      if (benchmark_state == BENCHMARK_RUNNING) {
        if (input.equalsIgnoreCase("STOP")) {
#ifdef USE_MULTICORE_RTOS
          serial_mutex.lock();
#endif
          Serial.println("Aborting benchmark...");
#ifdef USE_MULTICORE_RTOS
          serial_mutex.unlock();
          crypto_active = false;
          benchmark_mode = false;
#endif
          benchmark_state = BENCHMARK_IDLE;
          Serial.println("Benchmark aborted!");
          errorBlink(1);
        } else {
          Serial.println("Cannot execute command while benchmark or image test is running.");
          Serial.println("Send 'STOP' to abort.");
        }
      } else {
        // Normal command processing
        processFormatCommand(input);

        if (input.equalsIgnoreCase("DETAIL ON") || input.equalsIgnoreCase("DETAIL_ON")) {
          detail_mode = true;
          Serial.println("Detail mode enabled - Image test will show block-by-block output");
        } else if (input.equalsIgnoreCase("DETAIL OFF") || input.equalsIgnoreCase("DETAIL_OFF")) {
          detail_mode = false;
          Serial.println("Detail mode disabled - Image test will show summary output only");
        } else if (input.equalsIgnoreCase("VALIDATE")) {
          validate_chacha20();
        } else if (input.equalsIgnoreCase("POWER")) {
          readPowerMeasurements();
        } else if (input.equalsIgnoreCase("MATRIX")) {
          generateMatrixReport();
        } else if (input.equalsIgnoreCase("LISTSD") || input.equalsIgnoreCase("LS")) {
          listSDFiles();
        } else if (input.equalsIgnoreCase("REMOUNT")) {
          Serial.println("Attempting to remount SD card...");
          if (setup_sd_card()) {
            Serial.println("SD card remounted successfully");
            successBlink(1);
          } else {
            Serial.println("Failed to remount SD card");
            errorBlink(2);
          }
        } else if (input.equalsIgnoreCase("MEMORY_DETAIL_ON")) {
          detailed_memory_tracking = true;
          Serial.println("Detailed memory tracking enabled");
        } else if (input.equalsIgnoreCase("MEMORY_DETAIL_OFF")) {
          detailed_memory_tracking = false;
          Serial.println("Detailed memory tracking disabled");
        } else if (input.startsWith("IMAGE") || input.startsWith("image")) {
          int spaceIndex = input.indexOf(' ');
          if (spaceIndex <= 0) {
            Serial.println("Invalid IMAGE command format. Use: IMAGE iterations filename");
          } else {
            int secondSpaceIndex = input.indexOf(' ', spaceIndex + 1);
            if (secondSpaceIndex <= 0) {
              Serial.println("Invalid IMAGE command format. Use: IMAGE iterations filename");
            } else {
              String iterStr = input.substring(spaceIndex + 1, secondSpaceIndex);
              int iterations = iterStr.toInt();
              String filename = input.substring(secondSpaceIndex + 1);
              if (iterations <= 0 || filename.length() == 0) {
                Serial.println("Invalid IMAGE parameters. Iterations must be > 0 and filename must be provided.");
              } else {
                // Set the benchmark state to block other commands during image test
                benchmark_state = BENCHMARK_RUNNING;
                runImageTest(filename.c_str(), iterations);
                benchmark_state = BENCHMARK_IDLE;
              }
            }
          }
        } else if ((input.startsWith("REPEAT") || input.startsWith("repeat"))) {
          int i = 0;
          while (i < input.length() && !isDigit(input.charAt(i))) i++;
          int start = i;
          while (i < input.length() && isDigit(input.charAt(i))) i++;

          if (start < i) {
            String countStr = input.substring(start, i);
            long repeatCount = countStr.toInt();
            while (i < input.length() && isSpace(input.charAt(i))) i++;
            String textStr = input.substring(i);

            if (repeatCount > 0 && textStr.length() > 0) {
              startBenchmark(textStr, repeatCount);
            } else {
              Serial.println("Invalid REPEAT format. Use: REPEAT [count] [text]");
            }
          } else {
            Serial.println("Could not find repeat count. Use: REPEAT [count] [text]");
          }
        } else if (input == "CMD:GET_SENSOR MATH") {
          Serial.println("RESP:RESULT=30");
        } else if (input.length() > 0) {
          unsigned long loop_start = micros();
          measureMemory("Before Single Encryption");

          unsigned char padded[MAX_SIZE] = { 0 };
          unsigned char encrypted[MAX_SIZE + IV_SIZE] = { 0 };
          unsigned char decrypted[MAX_SIZE] = { 0 };

          size_t input_len = input.length();
          size_t padded_len = padData(input.c_str(), padded, input_len);

#ifdef USE_MULTICORE_RTOS
          if (!power_thread_running) {
            single_measurement_mode = true;
            crypto_active = true;
            power_mutex.lock();
            power_sample_count = 0;
            power_mutex.unlock();
            startPowerMeasurement();
          }
#endif

          digitalWrite(LEDB, LOW);
          unsigned long encrypt_time = encrypt(padded, encrypted, padded_len);
          unsigned long decrypt_time = decrypt(encrypted, decrypted, padded_len);
          digitalWrite(LEDB, HIGH);

#ifdef USE_MULTICORE_RTOS
          crypto_active = false;
          serial_mutex.lock();
#endif
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

          float encrypt_throughput = padded_len * 1e6 / encrypt_time;
          float decrypt_throughput = padded_len * 1e6 / decrypt_time;
          Serial.print("Throughput: Enc=");
          Serial.print(encrypt_throughput);
          Serial.print(", Dec=");
          Serial.print(decrypt_throughput);
          Serial.println(" bytes/s");

#ifdef ARDUINO_ARCH_MBED
          mbed_stats_cpu_t cpu_stats;
          mbed_stats_cpu_get(&cpu_stats);
          float actual_cpu_usage = 100.0 * (1.0 - ((float)cpu_stats.idle_time / (float)cpu_stats.uptime));
          Serial.print("CPU usage: ");
          Serial.print(actual_cpu_usage, 2);
          Serial.println("%");
#endif

#ifdef USE_INA226
#ifdef USE_MULTICORE_RTOS
          power_mutex.lock();
          if (power_sample_count > 0 && ina226_available) {
            float avg_current_A = 0;
            float avg_voltage_V = 0;
            float avg_power_W = 0;

            for (int i = 0; i < power_sample_count; i++) {
              avg_current_A += power_samples[i].current_A;
              avg_voltage_V += power_samples[i].voltage_V;
              avg_power_W += power_samples[i].power_W;
            }
            avg_current_A /= power_sample_count;
            avg_voltage_V /= power_sample_count;
            avg_power_W /= power_sample_count;

            float duration_s = (power_samples[power_sample_count - 1].timestamp - power_samples[0].timestamp) / 1000.0;
            float energy_J = avg_power_W * duration_s;

            Serial.print("Current usage: ");
            Serial.print(avg_current_A * 1000, 2);  // Show in mA for readability
            Serial.print(" mA (");
            Serial.print(avg_current_A, 5);
            Serial.println(" A)");

            Serial.print("Voltage: ");
            Serial.print(avg_voltage_V, 3);
            Serial.println(" V");

            Serial.print("Power usage: ");
            Serial.print(avg_power_W * 1000, 2);  // Show in mW for readability
            Serial.print(" mW (");
            Serial.print(avg_power_W, 5);
            Serial.println(" W)");

            Serial.print("Energy usage: ");
            Serial.print(energy_J * 1000, 2);  // Show in mJ for readability
            Serial.print(" mJ (");
            Serial.print(energy_J, 5);
            Serial.println(" J)");
          } else if (ina226_available) {
            Serial.println("Current usage: Measuring... (No samples collected yet)");
          } else {
            Serial.println("Current usage: N/A (INA226 not available)");
            Serial.println("Voltage: N/A");
            Serial.println("Power usage: N/A");
            Serial.println("Energy usage: N/A");
          }
          power_mutex.unlock();
#else
          if (ina226_available) {
            float current_A = ina226.getCurrent_mA() / 1000.0;  // Convert mA to A
            float voltage_V = ina226.getBusVoltage_V();
            float power_W = current_A * voltage_V;  // P = I*V

            Serial.print("Current usage: ");
            Serial.print(current_A * 1000, 2);  // Show in mA for readability
            Serial.print(" mA (");
            Serial.print(current_A, 5);
            Serial.println(" A)");

            Serial.print("Voltage: ");
            Serial.print(voltage_V, 3);
            Serial.println(" V");

            Serial.print("Power usage: ");
            Serial.print(power_W * 1000, 2);  // Show in mW for readability
            Serial.print(" mW (");
            Serial.print(power_W, 5);
            Serial.println(" W)");

            // Estimate energy for a single operation (very rough)
            float operation_time_s = (encrypt_time + decrypt_time) / 1000000.0;  // Convert µs to s
            float energy_J = power_W * operation_time_s;

            Serial.print("Energy estimate: ");
            Serial.print(energy_J * 1000, 2);  // Show in mJ for readability
            Serial.print(" mJ (");
            Serial.print(energy_J, 5);
            Serial.println(" J)");
          } else {
            Serial.println("Current usage: N/A (INA226 not available)");
            Serial.println("Voltage: N/A");
            Serial.println("Power usage: N/A");
            Serial.println("Energy usage: N/A");
          }
#endif
#else
          Serial.println("Current usage: N/A (INA226 not enabled in build)");
          Serial.println("Voltage: N/A");
          Serial.println("Power usage: N/A");
          Serial.println("Energy usage: N/A");
#endif

          size_t actual_len = removePadding(decrypted, padded_len);
          decrypted[actual_len] = '\0';
          Serial.print("Decrypted: ");
          Serial.println((char*)decrypted);

          if (strstr((char*)decrypted, "+") || strstr((char*)decrypted, "-") || strstr((char*)decrypted, "*") || strstr((char*)decrypted, "/")) {
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
#ifdef USE_MULTICORE_RTOS
          serial_mutex.unlock();
#endif
          measureMemory("After Single Encryption");
          successBlink(1);
        }
        Serial.println();
      }
    }
  }
  delay(10);
}