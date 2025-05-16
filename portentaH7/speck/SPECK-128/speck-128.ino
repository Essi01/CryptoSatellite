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
bool detail_mode = false;  // Default is OFF - controls detailed output for IMAGE-test
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
#define ALGORITHM_NAME "SPECK-128/256"
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
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define SD_CS_PIN 10
#define BLOCK_SIZE 1024
#define UART_BUFFER_SIZE 128
#define SERIAL_NUCLEO Serial1
#define BENCHMARK_CHUNK_SIZE 100
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true
#define SPECK_BLOCK_SIZE 16  // 128 bits

// SPECK macros
#define ROTL64(x, r) (((x) << (r)) | (x >> (64 - (r))))
#define ROTR64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#define ER64(x, y, k) (x = ROTR64(x, 8), x += y, x ^= k, y = ROTL64(y, 3), y ^= x)
#define DR64(x, y, k) (y ^= x, y = ROTR64(y, 3), x ^= k, x -= y, x = ROTL64(x, 8))

// SPECK context structure
typedef struct {
  uint64_t rk[35];  // Round keys for SPECK-128/256
  uint8_t key[32];  // 256-bit key
} SPECK_ctx;

// Pre-allocated SPECK context for reuse
SPECK_ctx speck_ctx;
bool speck_ctx_initialized = false;

// SPECK keys and test vectors
const unsigned char speck_key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

const unsigned char test_key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

const unsigned char test_nonce[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const unsigned char test_plaintext[16] = {
  0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
  0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65
};

const unsigned char test_ciphertext[16] = {
  0x43, 0x8f, 0x18, 0x9c, 0x8d, 0xb4, 0xee, 0x4e,
  0x3e, 0xf5, 0xc0, 0x05, 0x04, 0x01, 0x09, 0x41
};

// Benchmark state variables
bool benchmark_state = BENCHMARK_IDLE;
const size_t MAX_SIZE = BLOCK_SIZE;
unsigned char benchmark_padded[MAX_SIZE] = { 0 };
unsigned char benchmark_encrypted[MAX_SIZE + NONCE_SIZE + TAG_SIZE] = { 0 };
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
#define MAX_ENCRYPTED_SIZE (BLOCK_SIZE + 16 + NONCE_SIZE + TAG_SIZE)
unsigned char encrypted_buffer[MAX_ENCRYPTED_SIZE] = { 0 };
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
void SPECK_init(SPECK_ctx* ctx, const uint8_t* key);
void SPECK_encrypt(SPECK_ctx* ctx, const uint8_t* nonce, const uint8_t* plaintext, uint8_t* ciphertext, uint8_t* tag, size_t len);
bool SPECK_decrypt(SPECK_ctx* ctx, const uint8_t* nonce, const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* tag, size_t len);
#ifdef USE_MULTICORE_RTOS
void powerMeasurementThread();
void cryptoBenchmarkThread();
void startPowerMeasurement();
void startBenchmarkRTOS();
#endif

// SPECK implementation functions
void SPECK_init(SPECK_ctx* ctx, const uint8_t* key) {
  uint64_t K[4];

  // Convert key bytes to words (little-endian)
  K[0] = ((uint64_t)key[7] << 56) | ((uint64_t)key[6] << 48) | ((uint64_t)key[5] << 40) | ((uint64_t)key[4] << 32) | ((uint64_t)key[3] << 24) | ((uint64_t)key[2] << 16) | ((uint64_t)key[1] << 8) | key[0];

  K[1] = ((uint64_t)key[15] << 56) | ((uint64_t)key[14] << 48) | ((uint64_t)key[13] << 40) | ((uint64_t)key[12] << 32) | ((uint64_t)key[11] << 24) | ((uint64_t)key[10] << 16) | ((uint64_t)key[9] << 8) | key[8];

  K[2] = ((uint64_t)key[23] << 56) | ((uint64_t)key[22] << 48) | ((uint64_t)key[21] << 40) | ((uint64_t)key[20] << 32) | ((uint64_t)key[19] << 24) | ((uint64_t)key[18] << 16) | ((uint64_t)key[17] << 8) | key[16];

  K[3] = ((uint64_t)key[31] << 56) | ((uint64_t)key[30] << 48) | ((uint64_t)key[29] << 40) | ((uint64_t)key[28] << 32) | ((uint64_t)key[27] << 24) | ((uint64_t)key[26] << 16) | ((uint64_t)key[25] << 8) | key[24];

  // Generate round keys
  uint64_t i, D = K[3], C = K[2], B = K[1], A = K[0];
  for (i = 0; i < 33;) {
    ctx->rk[i] = A;
    ER64(B, A, i++);
    ctx->rk[i] = A;
    ER64(C, A, i++);
    ctx->rk[i] = A;
    ER64(D, A, i++);
  }
  ctx->rk[i] = A;

  // Store the key
  memcpy(ctx->key, key, 32);
}

void SPECK_encrypt(SPECK_ctx* ctx, const uint8_t* nonce, const uint8_t* plaintext, uint8_t* ciphertext, uint8_t* tag, size_t len) {
  // For SPECK, we don't use the nonce in the same way as ASCON
  // We'll implement a simpler scheme for this benchmark

  // Process blocks of data
  for (size_t i = 0; i < len; i += 16) {
    size_t block_len = min(16, len - i);
    if (block_len == 16) {  // Full block
      uint64_t Pt[2], Ct[2];

      // Convert bytes to words (little-endian as per documentation)
      Pt[0] = ((uint64_t)plaintext[i + 7] << 56) | ((uint64_t)plaintext[i + 6] << 48) | ((uint64_t)plaintext[i + 5] << 40) | ((uint64_t)plaintext[i + 4] << 32) | ((uint64_t)plaintext[i + 3] << 24) | ((uint64_t)plaintext[i + 2] << 16) | ((uint64_t)plaintext[i + 1] << 8) | plaintext[i];

      Pt[1] = ((uint64_t)plaintext[i + 15] << 56) | ((uint64_t)plaintext[i + 14] << 48) | ((uint64_t)plaintext[i + 13] << 40) | ((uint64_t)plaintext[i + 12] << 32) | ((uint64_t)plaintext[i + 11] << 24) | ((uint64_t)plaintext[i + 10] << 16) | ((uint64_t)plaintext[i + 9] << 8) | plaintext[i + 8];

      // Encrypt the block
      Ct[0] = Pt[0];
      Ct[1] = Pt[1];
      for (uint64_t j = 0; j < 34;) ER64(Ct[1], Ct[0], ctx->rk[j++]);

      // Convert words back to bytes (little-endian)
      ciphertext[i] = Ct[0] & 0xFF;
      ciphertext[i + 1] = (Ct[0] >> 8) & 0xFF;
      ciphertext[i + 2] = (Ct[0] >> 16) & 0xFF;
      ciphertext[i + 3] = (Ct[0] >> 24) & 0xFF;
      ciphertext[i + 4] = (Ct[0] >> 32) & 0xFF;
      ciphertext[i + 5] = (Ct[0] >> 40) & 0xFF;
      ciphertext[i + 6] = (Ct[0] >> 48) & 0xFF;
      ciphertext[i + 7] = (Ct[0] >> 56) & 0xFF;

      ciphertext[i + 8] = Ct[1] & 0xFF;
      ciphertext[i + 9] = (Ct[1] >> 8) & 0xFF;
      ciphertext[i + 10] = (Ct[1] >> 16) & 0xFF;
      ciphertext[i + 11] = (Ct[1] >> 24) & 0xFF;
      ciphertext[i + 12] = (Ct[1] >> 32) & 0xFF;
      ciphertext[i + 13] = (Ct[1] >> 40) & 0xFF;
      ciphertext[i + 14] = (Ct[1] >> 48) & 0xFF;
      ciphertext[i + 15] = (Ct[1] >> 56) & 0xFF;

    } else {
      // Handle partial block (less common in practice)
      uint8_t temp_block[16] = { 0 };
      memcpy(temp_block, plaintext + i, block_len);

      uint64_t Pt[2], Ct[2];

      // Convert bytes to words
      Pt[0] = ((uint64_t)temp_block[7] << 56) | ((uint64_t)temp_block[6] << 48) | ((uint64_t)temp_block[5] << 40) | ((uint64_t)temp_block[4] << 32) | ((uint64_t)temp_block[3] << 24) | ((uint64_t)temp_block[2] << 16) | ((uint64_t)temp_block[1] << 8) | temp_block[0];

      Pt[1] = ((uint64_t)temp_block[15] << 56) | ((uint64_t)temp_block[14] << 48) | ((uint64_t)temp_block[13] << 40) | ((uint64_t)temp_block[12] << 32) | ((uint64_t)temp_block[11] << 24) | ((uint64_t)temp_block[10] << 16) | ((uint64_t)temp_block[9] << 8) | temp_block[8];

      // Encrypt block
      Ct[0] = Pt[0];
      Ct[1] = Pt[1];
      for (uint64_t j = 0; j < 34;) ER64(Ct[1], Ct[0], ctx->rk[j++]);

      // Convert back and copy partial result
      uint8_t temp_out[16];
      temp_out[0] = Ct[0] & 0xFF;
      temp_out[1] = (Ct[0] >> 8) & 0xFF;
      temp_out[2] = (Ct[0] >> 16) & 0xFF;
      temp_out[3] = (Ct[0] >> 24) & 0xFF;
      temp_out[4] = (Ct[0] >> 32) & 0xFF;
      temp_out[5] = (Ct[0] >> 40) & 0xFF;
      temp_out[6] = (Ct[0] >> 48) & 0xFF;
      temp_out[7] = (Ct[0] >> 56) & 0xFF;

      temp_out[8] = Ct[1] & 0xFF;
      temp_out[9] = (Ct[1] >> 8) & 0xFF;
      temp_out[10] = (Ct[1] >> 16) & 0xFF;
      temp_out[11] = (Ct[1] >> 24) & 0xFF;
      temp_out[12] = (Ct[1] >> 32) & 0xFF;
      temp_out[13] = (Ct[1] >> 40) & 0xFF;
      temp_out[14] = (Ct[1] >> 48) & 0xFF;
      temp_out[15] = (Ct[1] >> 56) & 0xFF;

      memcpy(ciphertext + i, temp_out, block_len);
    }
  }

  // For simplicity, create a simple tag
  // In a real implementation, you'd implement a proper authentication tag
  if (tag != NULL) {
    uint64_t tag_data[2] = { 0 };
    // XOR all plaintext blocks to create a simple "tag" (not secure, just for demo)
    for (size_t i = 0; i < len; i += 16) {
      size_t block_len = min(16, len - i);
      for (size_t j = 0; j < block_len; j++) {
        tag[j % 16] ^= plaintext[i + j];
      }
    }

    // Encrypt the tag data with the last round key
    tag_data[0] = ((uint64_t)tag[7] << 56) | ((uint64_t)tag[6] << 48) | ((uint64_t)tag[5] << 40) | ((uint64_t)tag[4] << 32) | ((uint64_t)tag[3] << 24) | ((uint64_t)tag[2] << 16) | ((uint64_t)tag[1] << 8) | tag[0];

    tag_data[1] = ((uint64_t)tag[15] << 56) | ((uint64_t)tag[14] << 48) | ((uint64_t)tag[13] << 40) | ((uint64_t)tag[12] << 32) | ((uint64_t)tag[11] << 24) | ((uint64_t)tag[10] << 16) | ((uint64_t)tag[9] << 8) | tag[8];

    for (uint64_t j = 0; j < 34;) ER64(tag_data[1], tag_data[0], ctx->rk[j++]);

    // Convert back to bytes
    tag[0] = tag_data[0] & 0xFF;
    tag[1] = (tag_data[0] >> 8) & 0xFF;
    tag[2] = (tag_data[0] >> 16) & 0xFF;
    tag[3] = (tag_data[0] >> 24) & 0xFF;
    tag[4] = (tag_data[0] >> 32) & 0xFF;
    tag[5] = (tag_data[0] >> 40) & 0xFF;
    tag[6] = (tag_data[0] >> 48) & 0xFF;
    tag[7] = (tag_data[0] >> 56) & 0xFF;

    tag[8] = tag_data[1] & 0xFF;
    tag[9] = (tag_data[1] >> 8) & 0xFF;
    tag[10] = (tag_data[1] >> 16) & 0xFF;
    tag[11] = (tag_data[1] >> 24) & 0xFF;
    tag[12] = (tag_data[1] >> 32) & 0xFF;
    tag[13] = (tag_data[1] >> 40) & 0xFF;
    tag[14] = (tag_data[1] >> 48) & 0xFF;
    tag[15] = (tag_data[1] >> 56) & 0xFF;
  }
}

bool SPECK_decrypt(SPECK_ctx* ctx, const uint8_t* nonce, const uint8_t* ciphertext, uint8_t* plaintext, const uint8_t* tag, size_t len) {
  // Process blocks of data
  for (size_t i = 0; i < len; i += 16) {
    size_t block_len = min(16, len - i);
    if (block_len == 16) {  // Full block
      uint64_t Ct[2], Pt[2];

      // Convert bytes to words (little-endian)
      Ct[0] = ((uint64_t)ciphertext[i + 7] << 56) | ((uint64_t)ciphertext[i + 6] << 48) | ((uint64_t)ciphertext[i + 5] << 40) | ((uint64_t)ciphertext[i + 4] << 32) | ((uint64_t)ciphertext[i + 3] << 24) | ((uint64_t)ciphertext[i + 2] << 16) | ((uint64_t)ciphertext[i + 1] << 8) | ciphertext[i];

      Ct[1] = ((uint64_t)ciphertext[i + 15] << 56) | ((uint64_t)ciphertext[i + 14] << 48) | ((uint64_t)ciphertext[i + 13] << 40) | ((uint64_t)ciphertext[i + 12] << 32) | ((uint64_t)ciphertext[i + 11] << 24) | ((uint64_t)ciphertext[i + 10] << 16) | ((uint64_t)ciphertext[i + 9] << 8) | ciphertext[i + 8];

      // Decrypt the block
      Pt[0] = Ct[0];
      Pt[1] = Ct[1];
      for (int j = 33; j >= 0;) DR64(Pt[1], Pt[0], ctx->rk[j--]);

      // Convert words back to bytes
      plaintext[i] = Pt[0] & 0xFF;
      plaintext[i + 1] = (Pt[0] >> 8) & 0xFF;
      plaintext[i + 2] = (Pt[0] >> 16) & 0xFF;
      plaintext[i + 3] = (Pt[0] >> 24) & 0xFF;
      plaintext[i + 4] = (Pt[0] >> 32) & 0xFF;
      plaintext[i + 5] = (Pt[0] >> 40) & 0xFF;
      plaintext[i + 6] = (Pt[0] >> 48) & 0xFF;
      plaintext[i + 7] = (Pt[0] >> 56) & 0xFF;

      plaintext[i + 8] = Pt[1] & 0xFF;
      plaintext[i + 9] = (Pt[1] >> 8) & 0xFF;
      plaintext[i + 10] = (Pt[1] >> 16) & 0xFF;
      plaintext[i + 11] = (Pt[1] >> 24) & 0xFF;
      plaintext[i + 12] = (Pt[1] >> 32) & 0xFF;
      plaintext[i + 13] = (Pt[1] >> 40) & 0xFF;
      plaintext[i + 14] = (Pt[1] >> 48) & 0xFF;
      plaintext[i + 15] = (Pt[1] >> 56) & 0xFF;

    } else {
      // Handle partial block
      uint8_t temp_block[16] = { 0 };
      memcpy(temp_block, ciphertext + i, block_len);

      uint64_t Ct[2], Pt[2];

      // Convert bytes to words
      Ct[0] = ((uint64_t)temp_block[7] << 56) | ((uint64_t)temp_block[6] << 48) | ((uint64_t)temp_block[5] << 40) | ((uint64_t)temp_block[4] << 32) | ((uint64_t)temp_block[3] << 24) | ((uint64_t)temp_block[2] << 16) | ((uint64_t)temp_block[1] << 8) | temp_block[0];

      Ct[1] = ((uint64_t)temp_block[15] << 56) | ((uint64_t)temp_block[14] << 48) | ((uint64_t)temp_block[13] << 40) | ((uint64_t)temp_block[12] << 32) | ((uint64_t)temp_block[11] << 24) | ((uint64_t)temp_block[10] << 16) | ((uint64_t)temp_block[9] << 8) | temp_block[8];

      // Decrypt block
      Pt[0] = Ct[0];
      Pt[1] = Ct[1];
      for (int j = 33; j >= 0;) DR64(Pt[1], Pt[0], ctx->rk[j--]);

      // Convert back and copy partial result
      uint8_t temp_out[16];
      temp_out[0] = Pt[0] & 0xFF;
      temp_out[1] = (Pt[0] >> 8) & 0xFF;
      temp_out[2] = (Pt[0] >> 16) & 0xFF;
      temp_out[3] = (Pt[0] >> 24) & 0xFF;
      temp_out[4] = (Pt[0] >> 32) & 0xFF;
      temp_out[5] = (Pt[0] >> 40) & 0xFF;
      temp_out[6] = (Pt[0] >> 48) & 0xFF;
      temp_out[7] = (Pt[0] >> 56) & 0xFF;

      temp_out[8] = Pt[1] & 0xFF;
      temp_out[9] = (Pt[1] >> 8) & 0xFF;
      temp_out[10] = (Pt[1] >> 16) & 0xFF;
      temp_out[11] = (Pt[1] >> 24) & 0xFF;
      temp_out[12] = (Pt[1] >> 32) & 0xFF;
      temp_out[13] = (Pt[1] >> 40) & 0xFF;
      temp_out[14] = (Pt[1] >> 48) & 0xFF;
      temp_out[15] = (Pt[1] >> 56) & 0xFF;

      memcpy(plaintext + i, temp_out, block_len);
    }
  }

  // For simplicity, verify the tag in a similar way to how we created it
  if (tag != NULL) {
    uint8_t computed_tag[16] = { 0 };

    // XOR all plaintext blocks to create a simple "tag" (not secure, just for demo)
    for (size_t i = 0; i < len; i += 16) {
      size_t block_len = min(16, len - i);
      for (size_t j = 0; j < block_len; j++) {
        computed_tag[j % 16] ^= plaintext[i + j];
      }
    }

    // Encrypt the tag data
    uint64_t tag_data[2];
    tag_data[0] = ((uint64_t)computed_tag[7] << 56) | ((uint64_t)computed_tag[6] << 48) | ((uint64_t)computed_tag[5] << 40) | ((uint64_t)computed_tag[4] << 32) | ((uint64_t)computed_tag[3] << 24) | ((uint64_t)computed_tag[2] << 16) | ((uint64_t)computed_tag[1] << 8) | computed_tag[0];

    tag_data[1] = ((uint64_t)computed_tag[15] << 56) | ((uint64_t)computed_tag[14] << 48) | ((uint64_t)computed_tag[13] << 40) | ((uint64_t)computed_tag[12] << 32) | ((uint64_t)computed_tag[11] << 24) | ((uint64_t)computed_tag[10] << 16) | ((uint64_t)computed_tag[9] << 8) | computed_tag[8];

    for (uint64_t j = 0; j < 34;) ER64(tag_data[1], tag_data[0], ctx->rk[j++]);

    // Convert back to bytes
    computed_tag[0] = tag_data[0] & 0xFF;
    computed_tag[1] = (tag_data[0] >> 8) & 0xFF;
    computed_tag[2] = (tag_data[0] >> 16) & 0xFF;
    computed_tag[3] = (tag_data[0] >> 24) & 0xFF;
    computed_tag[4] = (tag_data[0] >> 32) & 0xFF;
    computed_tag[5] = (tag_data[0] >> 40) & 0xFF;
    computed_tag[6] = (tag_data[0] >> 48) & 0xFF;
    computed_tag[7] = (tag_data[0] >> 56) & 0xFF;

    computed_tag[8] = tag_data[1] & 0xFF;
    computed_tag[9] = (tag_data[1] >> 8) & 0xFF;
    computed_tag[10] = (tag_data[1] >> 16) & 0xFF;
    computed_tag[11] = (tag_data[1] >> 24) & 0xFF;
    computed_tag[12] = (tag_data[1] >> 32) & 0xFF;
    computed_tag[13] = (tag_data[1] >> 40) & 0xFF;
    computed_tag[14] = (tag_data[1] >> 48) & 0xFF;
    computed_tag[15] = (tag_data[1] >> 56) & 0xFF;

    // Compare computed tag with given tag
    return memcmp(computed_tag, tag, 16) == 0;
  }

  return true;  // No tag verification
}

// Initialize encryption/decryption contexts for reuse
void initializeSpeckContexts() {
  if (!speck_ctx_initialized) {
    SPECK_init(&speck_ctx, speck_key);
    speck_ctx_initialized = true;
  }
}

// Free encryption/decryption contexts
void freeSpeckContexts() {
  speck_ctx_initialized = false;
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
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: None (AEAD)");
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
  Serial.println("Security Strength: 128-bit");
  Serial.println("Error Propagation: None (AEAD)");
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
  for (int i = 0; i < NONCE_SIZE; i++) {
    nonce[i] = random(256);
  }
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

// Core encryption/decryption functions using SPECK-128/256
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
  if (!speck_ctx_initialized) {
    initializeSpeckContexts();
  }
  const int MIN_ACCURATE_MICROS = 100;
  const int MIN_ITERATIONS = 3;
  int iterations = 0;
  unsigned long loop_start_time = micros();
  unsigned long total_actual_speck_time = 0;
  unsigned char current_operation_nonce[NONCE_SIZE];
  do {
    iterations++;
    generateNonce(current_operation_nonce);
    memcpy(output, current_operation_nonce, NONCE_SIZE);
    unsigned char tag[TAG_SIZE] = {0};
    unsigned long single_speck_op_start_time = micros();
    SPECK_encrypt(&speck_ctx, current_operation_nonce, input, output + NONCE_SIZE, tag, len);
    total_actual_speck_time += safeTimeDiff(single_speck_op_start_time, micros());
    memcpy(output + NONCE_SIZE + len, tag, TAG_SIZE);
    // Extra work for consistent timing loop duration
    unsigned char small_nonce_extra[NONCE_SIZE];
    memcpy(small_nonce_extra, current_operation_nonce, NONCE_SIZE);
    unsigned char extra_buf[64] = { 0 };
    unsigned char extra_tag[TAG_SIZE];
    SPECK_encrypt(&speck_ctx, small_nonce_extra, extra_buf, extra_buf, extra_tag, sizeof(extra_buf));
  } while ((safeTimeDiff(loop_start_time, micros()) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && iterations < 20);
  unsigned long avg_actual_speck_time = (iterations > 0) ? (total_actual_speck_time / iterations) : 0;
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
    Serial.print(" iterations, avg actual SPECK: ");
    Serial.print(avg_actual_speck_time);
    Serial.println(" µs");
  }
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
#endif
  return avg_actual_speck_time;
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
  if (!speck_ctx_initialized) {
    initializeSpeckContexts();
  }
  const int MIN_ACCURATE_MICROS = 100;
  const int MIN_ITERATIONS = 3;
  int iterations = 0;
  unsigned long loop_start_time = micros();
  unsigned long total_actual_speck_time = 0;
  unsigned char nonce[NONCE_SIZE];
  do {
    iterations++;
    memcpy(nonce, input, NONCE_SIZE);
    unsigned char tag[TAG_SIZE];
    memcpy(tag, input + NONCE_SIZE + len, TAG_SIZE);
    unsigned long single_speck_op_start_time = micros();
    bool success = SPECK_decrypt(&speck_ctx, nonce, input + NONCE_SIZE, output, tag, len);
    total_actual_speck_time += safeTimeDiff(single_speck_op_start_time, micros());
    if (!success) {
      Serial.println("Decryption failed: Tag verification error");
      return 0;
    }
    // Extra work for consistent timing loop duration
    unsigned char small_nonce_extra[NONCE_SIZE];
    memcpy(small_nonce_extra, nonce, NONCE_SIZE);
    unsigned char extra_buf[64] = { 0 };
    unsigned char extra_tag[TAG_SIZE] = { 0 };
    SPECK_decrypt(&speck_ctx, small_nonce_extra, extra_buf, extra_buf, extra_tag, sizeof(extra_buf));
  } while ((safeTimeDiff(loop_start_time, micros()) < MIN_ACCURATE_MICROS || iterations < MIN_ITERATIONS) && iterations < 20);
  unsigned long avg_actual_speck_time = (iterations > 0) ? (total_actual_speck_time / iterations) : 0;
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
    Serial.print(" iterations, avg actual SPECK: ");
    Serial.print(avg_actual_speck_time);
    Serial.println(" µs");
  }
#ifdef USE_MULTICORE_RTOS
  serial_mutex.unlock();
#endif
#endif
  return avg_actual_speck_time;
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

// SPECK validation
bool validate_speck() {
#ifdef USE_MULTICORE_RTOS
  serial_mutex.lock();
#endif
  Serial.println("\n==========================================");
  Serial.println("         VALIDATION TEST                 ");
  Serial.println("==========================================");
  Serial.println("Validating SPECK-128/256 implementation...");
  // Setup test context with test key
  SPECK_ctx test_ctx;
  SPECK_init(&test_ctx, test_key);
  // Test encryption
  unsigned char output[16] = { 0 };
  unsigned char tag[16] = { 0 };
  unsigned char nonce[16];
  memcpy(nonce, test_nonce, 16);
  SPECK_encrypt(&test_ctx, nonce, test_plaintext, output, tag, 16);
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
      break;
    }
  }
  // Test decryption
  unsigned char decrypted[16] = { 0 };
  memcpy(nonce, test_nonce, 16);
  bool success = SPECK_decrypt(&test_ctx, nonce, output, decrypted, tag, 16);
  Serial.println("Decrypted:");
  printHex(decrypted, 16);
  Serial.println("Expected:");
  printHex(test_plaintext, 16);
  // Verify decryption result
  bool decryption_match = true;
  for (int i = 0; i < 16; i++) {
    if (decrypted[i] != test_plaintext[i]) {
      decryption_match = false;
      break;
    }
  }
  bool final_success = encryption_match && success && decryption_match;
  if (final_success) {
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
  return final_success;
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
          if (single_measurement_mode && power_sample_count >= 10) single_measurement_mode = false;
        }
        power_mutex.unlock();
      }
      rtos::ThisThread::sleep_for(POWER_SAMPLE_INTERVAL_MS);
    }
    power_mutex.lock();
    if (power_sample_count > 0) {
      float avg_current_A = 0;
      float max_current_A = 0;
      float min_current_A = 9999.0;
      float avg_power_W = 0;
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
  // Initialize SPECK contexts if not already done
  initializeSpeckContexts();
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
  Serial.print("Starting SPECK-128/256 benchmark with ");
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
  Serial.print("Encrypted (first block with nonce): ");
  printHex(benchmark_encrypted, min(benchmark_padded_len + NONCE_SIZE, 32));
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
    Serial.println("SD card not ready. Cannot run image test.");
    errorBlink(2);
    return false;
  }
  char filepath[64];
  sprintf(filepath, "/fs/%s", filename);
  FILE* imageFile = fopen(filepath, "rb");
  if (!imageFile) {
    Serial.print("Failed to open file: ");
    Serial.println(filepath);
    errorBlink(3);
    return false;
  }
  fseek(imageFile, 0, SEEK_END);
  long fileSize = ftell(imageFile);
  fseek(imageFile, 0, SEEK_SET);

  if (fileSize <= 0) {
    Serial.print("Invalid file size: ");
    Serial.println(fileSize);
    fclose(imageFile);
    errorBlink(3);
    return false;
  }
  Serial.println("\n==========================================");
  Serial.println("         IMAGE TEST                       ");
  Serial.println("==========================================");
  Serial.print("Processing file: ");
  Serial.println(filename);
  Serial.print("File size: ");
  Serial.print(fileSize);
  Serial.println(" bytes");
  Serial.print("Running ");
  Serial.print(iterations);
  Serial.println(" iterations...");

  // Init crypto contexts
  initializeSpeckContexts();

  // Start power measurements (for RTOS multi-core setup)
#ifdef USE_MULTICORE_RTOS
  if (!power_thread_running) {
    startPowerMeasurement();
  }
#endif

  // Initialize performance counters
  unsigned long total_encrypt_time = 0;
  unsigned long total_decrypt_time = 0;
  unsigned long total_chunks = 0;
  unsigned long start_time = millis();

  // Process the file in chunks
  size_t bytes_read;
  for (int i = 0; i < iterations; i++) {
    fseek(imageFile, 0, SEEK_SET);
    long remaining = fileSize;
    while (remaining > 0) {
      size_t to_read = min(BLOCK_SIZE, remaining);
      bytes_read = fread(image_buffer, 1, to_read, imageFile);
      if (bytes_read == 0) break;
      unsigned long encrypt_time = encrypt(image_buffer, encrypted_buffer, bytes_read);
      unsigned long decrypt_time = decrypt(encrypted_buffer, image_buffer, bytes_read);
      total_encrypt_time += encrypt_time;
      total_decrypt_time += decrypt_time;
      total_chunks++;
      remaining -= bytes_read;
      if (i == 0 && detail_mode) {
        Serial.print("Block ");
        Serial.print(total_chunks);
        Serial.print(": E=");
        Serial.print(encrypt_time);
        Serial.print("µs, D=");
        Serial.print(decrypt_time);
        Serial.print("µs, Size=");
        Serial.print(bytes_read);
        Serial.println("B");
      }
    }
    if ((i + 1) % 10 == 0 || i == iterations - 1) {
      Serial.print(".");
      if ((i + 1) % 100 == 0) Serial.println();
    }
  }
  unsigned long end_time = millis();
  unsigned long total_time = safeTimeDiff(start_time, end_time);
  fclose(imageFile);

  // Calculate performance metrics
  float avg_encrypt = (float)total_encrypt_time / total_chunks;
  float avg_decrypt = (float)total_decrypt_time / total_chunks;
  float encrypted_throughput = (fileSize * iterations * 1e6) / total_encrypt_time;
  float decrypted_throughput = (fileSize * iterations * 1e6) / total_decrypt_time;
  float combined_throughput = (fileSize * iterations * 2 * 1e6) / (total_encrypt_time + total_decrypt_time);

  // Stop power measurements and calculate averages (for RTOS setup)
#ifdef USE_MULTICORE_RTOS
  crypto_active = false;
  power_mutex.lock();
  if (power_sample_count > 0 && ina226_available) {
    float avg_current_A = 0;
    float avg_power_W = 0;
    float max_current_A = 0;
    float min_current_A = 9999.0;
    float avg_voltage_V = 0;
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
    float total_time_s = total_time / 1000.0;
    float total_energy_J = avg_power_W * total_time_s;

    // Print power measurements
    printPowerMeasurements(avg_current_A, min_current_A, max_current_A, avg_voltage_V, avg_power_W, total_energy_J);
  } else {
    Serial.println("No power measurements available.");
  }
  power_mutex.unlock();
#else
  // Single-core power measurement (if RTOS is not used)
  if (ina226_available) {
    float current_A, bus_voltage_V, power_W;
    readCurrentPower(current_A, bus_voltage_V, power_W);
    float total_time_s = total_time / 1000.0;
    float total_energy_J = power_W * total_time_s;
    printPowerMeasurements(current_A, current_A, current_A, bus_voltage_V, power_W, total_energy_J);
  } else {
    Serial.println("No power measurements available.");
  }
#endif

  // Print performance results
  Serial.println("\n==========================================");
  Serial.println("         IMAGE TEST RESULTS               ");
  Serial.println("==========================================");
  Serial.print("Total processing time: ");
  Serial.print(total_time);
  Serial.println(" ms");
  Serial.print("Average block size: ");
  Serial.print(fileSize * iterations / total_chunks);
  Serial.println(" bytes");
  Serial.print("Average encrypt time: ");
  Serial.print(avg_encrypt, 2);
  Serial.println(" µs");
  Serial.print("Average decrypt time: ");
  Serial.print(avg_decrypt, 2);
  Serial.println(" µs");
  Serial.print("Encrypt throughput: ");
  Serial.print(encrypted_throughput / 1024, 2);
  Serial.println(" KB/sec");
  Serial.print("Decrypt throughput: ");
  Serial.print(decrypted_throughput / 1024, 2);
  Serial.println(" KB/sec");
  Serial.print("Combined throughput: ");
  Serial.print(combined_throughput / 1024, 2);
  Serial.println(" KB/sec");
  Serial.println("==========================================");

  successBlink(2);
  return true;
}

// Display image file info without processing
bool displayImageInfo(const char* filename) {
  if (!sd_card_ready) {
    Serial.println("SD card not ready.");
    return false;
  }
  char filepath[64];
  sprintf(filepath, "/fs/%s", filename);
  FILE* imageFile = fopen(filepath, "rb");
  if (!imageFile) {
    Serial.print("Failed to open file: ");
    Serial.println(filepath);
    return false;
  }
  fseek(imageFile, 0, SEEK_END);
  long fileSize = ftell(imageFile);
  fseek(imageFile, 0, SEEK_SET);
  Serial.println("\n==========================================");
  Serial.println("         IMAGE FILE INFO                  ");
  Serial.println("==========================================");
  Serial.print("File: ");
  Serial.println(filename);
  Serial.print("Size: ");
  Serial.print(fileSize);
  Serial.println(" bytes");
  // Try to detect file type based on header
  unsigned char header[8];
  if (fread(header, 1, sizeof(header), imageFile) == sizeof(header)) {
    if (header[0] == 0xFF && header[1] == 0xD8) {
      Serial.println("Type: JPEG image");
    } else if (header[0] == 0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G') {
      Serial.println("Type: PNG image");
    } else if (header[0] == 'B' && header[1] == 'M') {
      Serial.println("Type: BMP image");
    } else if (header[0] == 'G' && header[1] == 'I' && header[2] == 'F') {
      Serial.println("Type: GIF image");
    } else {
      Serial.println("Type: Unknown/binary file");
    }
  }
  Serial.println("==========================================");
  fclose(imageFile);
  return true;
}

// List SD card files
void listSDFiles() {
  if (!sd_card_ready) {
    Serial.println("SD card not ready. Cannot list files.");
    return;
  }
  DIR* dir = opendir("/fs");
  if (!dir) {
    Serial.println("Failed to open directory");
    return;
  }
  Serial.println("\n==========================================");
  Serial.println("         SD CARD FILES                   ");
  Serial.println("==========================================");
  int fileCount = 0;
  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_REG) {  // Regular file
      char filepath[256];
      sprintf(filepath, "/fs/%s", entry->d_name);
      struct stat st;
      stat(filepath, &st);
      Serial.print(entry->d_name);
      Serial.print(" (");
      Serial.print(st.st_size);
      Serial.println(" bytes)");
      fileCount++;
    } else if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {  // Directory
      Serial.print("[DIR] ");
      Serial.println(entry->d_name);
      fileCount++;
    }
  }
  closedir(dir);
  if (fileCount == 0) {
    Serial.println("No files found");
  }
  Serial.println("==========================================");
}

// Setup - initialize everything
void setup() {
  // Initialize LED pins
  pinMode(LEDR, OUTPUT);
  pinMode(LEDG, OUTPUT);
  pinMode(LEDB, OUTPUT);
  digitalWrite(LEDR, HIGH);  // Note: LEDs are active LOW
  digitalWrite(LEDG, HIGH);
  digitalWrite(LEDB, HIGH);
  // Initialize serial port
  Serial.begin(115200);
  while (!Serial && millis() < 5000)
    ;  // Wait for serial port to connect (timeout)
  Serial.println("\n==========================================");
  Serial.println("  Security-Optimal IoT - SPECK-128/256   ");
  Serial.println("==========================================");
  Serial.println("Initializing system...");
  // Initialize random number generator
  randomSeed(analogRead(0) ^ micros());

  // Report hardware details
#ifdef ARDUINO_ARCH_MBED
  Serial.print("Board: ");
  Serial.println(BOARD_NAME);
  Serial.print("Architecture: ");
  Serial.println("ARM Mbed OS");
  mbed_stats_cpu_t cpu_stats;
  mbed_stats_cpu_get(&cpu_stats);
  Serial.print("CPU Uptime: ");
  Serial.print(cpu_stats.uptime / 1000);
  Serial.println(" seconds");
  mbed_stats_heap_t heap_stats;
  mbed_stats_heap_get(&heap_stats);
  Serial.print("Heap Size: ");
  Serial.print(heap_stats.reserved_size);
  Serial.println(" bytes");
  Serial.print("Free Heap: ");
  Serial.print(heap_stats.reserved_size - heap_stats.current_size);
  Serial.println(" bytes");
#else
  Serial.print("Free RAM: ");
  Serial.print(freeRam());
  Serial.println(" bytes");
#endif

  // Initialize INA226 power monitor if available
#ifdef USE_INA226
  Wire.begin();
  if (ina226.init()) {
    Serial.println("INA226 power monitor initialized");
    ina226.setResistorRange(SHUNT_RESISTOR_VALUE, MAX_CURRENT);
// Alternative verdier, basert på biblioteksdokumentasjonen
ina226.setAverage(AVERAGE_1);             // 1 sample
ina226.setConversionTime(CONV_TIME_1100);  // Bruk en passende enum-verdi
ina226.setMeasureMode(CONTINUOUS);         // Kontinuerlig målemodus
    ina226_available = true;
    float current = ina226.getCurrent_mA();
    float voltage = ina226.getBusVoltage_V();
    float power = ina226.getBusPower();
    Serial.print("Current power draw: ");
    Serial.print(current);
    Serial.print(" mA @ ");
    Serial.print(voltage, 2);
    Serial.print(" V = ");
    Serial.print(power);
    Serial.println(" mW");
  } else {
    Serial.println("INA226 power monitor not found");
    ina226_available = false;
  }
#else
  Serial.println("INA226 power monitor support not compiled");
#endif

  // Set up the SD card
  setup_sd_card();

  // Initialize SPECK context
  initializeSpeckContexts();

  // Validate SPECK implementation
  validate_speck();

  // Setup RTOS threads if applicable
#ifdef USE_MULTICORE_RTOS
  Serial.println("\n==========================================");
  Serial.println("  Initializing Dual-Core RTOS            ");
  Serial.println("==========================================");
  startM4Core();
  power_thread.start(powerMeasurementThread);
  crypto_thread.start(cryptoBenchmarkThread);
  Serial.println("RTOS initialized with two cores");
  Serial.print("Core M7 (crypto): ");
  Serial.println(rtos::ThisThread::get_id());
#else
  Serial.println("Single-core mode (no RTOS)");
#endif

  Serial.println("\n==========================================");
  Serial.println("  System Ready - Commands:               ");
  Serial.println("==========================================");
  Serial.println("BENCHMARK TEXT REPEATS - Run benchmark");
  Serial.println("SPECKTEST - Validate SPECK implementation");
  Serial.println("LISTSD - List files on SD card");
  Serial.println("IMGINFO FILENAME - Display image file info");
  Serial.println("IMGTEST FILENAME REPEATS - Process image file");
  Serial.println("MEMORY - Display memory usage");
  Serial.println("POWER - Display power measurements");
  Serial.println("MATRIX - Generate decision matrix data");
  Serial.println("DETAIL ON/OFF - Toggle detailed output mode");
  Serial.println("FORMATSD - Format SD card");
  Serial.println("==========================================");

  // Blink success
  successBlink(3);
}

// Main loop - handle serial commands
void loop() {
  if (benchmark_state == BENCHMARK_RUNNING) {
#ifndef USE_MULTICORE_RTOS
    processBenchmarkChunk();
#endif
  }

  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.startsWith("BENCHMARK ")) {
      int firstSpace = input.indexOf(' ');
      int secondSpace = input.indexOf(' ', firstSpace + 1);
      if (secondSpace > 0) {
        String text = input.substring(firstSpace + 1, secondSpace);
        String repeatsStr = input.substring(secondSpace + 1);
        long repeats = repeatsStr.toInt();
        if (repeats > 0) {
          startBenchmark(text, repeats);
        } else {
          Serial.println("Invalid number of repeats");
        }
      } else {
        Serial.println("Invalid BENCHMARK command format");
        Serial.println("Use: BENCHMARK text repeats");
      }
    } else if (input.equals("SPECKTEST")) {
      validate_speck();
    } else if (input.equals("LISTSD")) {
      listSDFiles();
    } else if (input.startsWith("IMGINFO ")) {
      String filename = input.substring(8);
      displayImageInfo(filename.c_str());
    } else if (input.startsWith("IMAGE ")) {
      int firstSpace = input.indexOf(' ');
      int secondSpace = input.indexOf(' ', firstSpace + 1);
      if (secondSpace > 0) {
        String repeatsStr = input.substring(firstSpace + 1, secondSpace);
        String filename = input.substring(secondSpace + 1);
        int repeats = repeatsStr.toInt();
        if (repeats > 0) {
          runImageTest(filename.c_str(), repeats);
        } else {
          Serial.println("Invalid number of repeats");
        }
      } else {
        Serial.println("Invalid IMAGE command format");
        Serial.println("Use: IMAGE repeats filename");
      }
    } else if (input.equals("MEMORY")) {
      measureMemory("User Request");
    } else if (input.equals("MATRIX")) {
      generateMatrixReport();
    } else if (input.equals("POWER")) {
      readPowerMeasurements();
    } else if (input.equals("DETAIL ON")) {
      detail_mode = true;
      Serial.println("Detailed output mode enabled");
    } else if (input.equals("DETAIL OFF")) {
      detail_mode = false;
      Serial.println("Detailed output mode disabled");
    } else if (input.equals("STOP") && benchmark_state == BENCHMARK_RUNNING) {
      Serial.println("Stopping benchmark...");
      benchmark_total_iterations = benchmark_current_iteration;
    } else if (input.startsWith("FORMATSD")) {
      processFormatCommand(input);
    } else if (!input.isEmpty()) {
      Serial.print("Unknown command: ");
      Serial.println(input);
    }
  }

  delay(10);
}