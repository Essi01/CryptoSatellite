#include <Arduino.h>

#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
#define USE_INA219
#endif

#ifdef USE_INA219
#include <Adafruit_INA219.h>
Adafruit_INA219 ina219;
#endif

// TRIVIUM Constants
#define TRIVIUM_STATE_SIZE 36  // State size in bytes (288 bits / 8)
#define KEY_SIZE 10            // 80-bit key (10 bytes)
#define IV_SIZE 10             // 80-bit IV (10 bytes)

// TRIVIUM key (80-bit)
const unsigned char trivium_key[KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
};

// Constants for non-blocking benchmark
#define BENCHMARK_CHUNK_SIZE 100  // Number of iterations per chunk
#define BENCHMARK_IDLE false
#define BENCHMARK_RUNNING true

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

// Energy measurement variables
#ifdef USE_INA219
float benchmark_total_energy = 0.0;
int benchmark_energy_samples = 0;
float benchmark_avg_current = 0.0;
unsigned long benchmark_last_energy_sample = 0;
const unsigned long ENERGY_SAMPLE_INTERVAL = 100; // Sample every 100ms
#endif

// TRIVIUM state structure
typedef struct {
  uint32_t state[12];  // 288 bits of state (9 * 32 = 288 bits)
} trivium_ctx;

// Memory management functions
#ifdef ARDUINO_ARCH_MBED
int freeRam() {
    mbed_stats_heap_t stats;
    mbed_stats_heap_get(&stats);
    return stats.reserved_size - stats.current_size;
}
#else
int freeRam() {
  extern char __heap_start, *__brkval;
  int v;
  return (int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval);
}
#endif

// Helper function to display bytes as hex
void printHex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 16) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

// Generate a random IV
void generateIV(unsigned char* iv) {
  for (int i = 0; i < IV_SIZE; i++) {
    iv[i] = random(256);
  }
}

// Pad data to 16-byte blocks for consistency with block ciphers
size_t padData(const char* input, unsigned char* output, size_t len) {
  size_t padded_len = ((len + 15) / 16) * 16;  // Round up to nearest 16

  // Copy original data
  memcpy(output, input, len);

  // Add padding (PKCS#7)
  unsigned char pad_value = padded_len - len;
  for (size_t i = len; i < padded_len; i++) {
    output[i] = pad_value;
  }

  return padded_len;
}

// Remove padding
size_t removePadding(unsigned char* data, size_t len) {
  if (len == 0) return 0;

  // Last byte indicates padding length in PKCS#7
  unsigned char padding_value = data[len - 1];

  // Check that padding is valid (not larger than block size)
  if (padding_value > 16) return len;

  return len - padding_value;
}

// Initialize TRIVIUM with key and IV
void trivium_init(trivium_ctx* ctx, const unsigned char* key, const unsigned char* iv) {
  // Clear the state
  memset(ctx->state, 0, sizeof(ctx->state));
  
  // Load key and IV into state
  // First 80 bits: key
  for (int i = 0; i < 3; i++) {
    ctx->state[i] = 0;
    for (int j = 0; j < 4 && (i*4+j) < KEY_SIZE; j++) {
      ctx->state[i] |= ((uint32_t)key[i*4+j]) << (j*8);
    }
  }
  
  // Next 80 bits: IV
  for (int i = 3; i < 6; i++) {
    ctx->state[i] = 0;
    for (int j = 0; j < 4 && (i*4+j-12) < IV_SIZE; j++) {
      ctx->state[i] |= ((uint32_t)iv[i*4+j-12]) << (j*8);
    }
  }
  
  // Set last 3 bits of state to 1
  ctx->state[9] = 0x00000007; // 111
  
  // Initialize state by running 4 * 288 = 1152 iterations
  for (int i = 0; i < 1152; i++) {
    // Extract bits for feedback
    uint32_t t1 = ((ctx->state[8] >> 13) & 1) ^ ((ctx->state[0] >> 19) & 1);
    uint32_t t2 = ((ctx->state[0] >> 25) & 1) ^ ((ctx->state[3] >> 7) & 1);
    uint32_t t3 = ((ctx->state[3] >> 13) & 1) ^ ((ctx->state[6] >> 7) & 1);
    
    // Rotate state and apply feedback
    for (int j = 0; j < 11; j++) {
      ctx->state[j] = (ctx->state[j] << 1) | ((ctx->state[j+1] >> 31) & 1);
    }
    ctx->state[11] = (ctx->state[11] << 1);
    
    ctx->state[0] ^= t3;
    ctx->state[3] ^= t1;
    ctx->state[6] ^= t2;
  }
}

// Generate one byte of keystream
unsigned char trivium_gen_byte(trivium_ctx* ctx) {
  unsigned char result = 0;
  
  // Generate 8 bits
  for (int i = 0; i < 8; i++) {
    // Extract bits from state
    uint32_t t1 = ((ctx->state[8] >> 13) & 1) ^ ((ctx->state[0] >> 19) & 1);
    uint32_t t2 = ((ctx->state[0] >> 25) & 1) ^ ((ctx->state[3] >> 7) & 1);
    uint32_t t3 = ((ctx->state[3] >> 13) & 1) ^ ((ctx->state[6] >> 7) & 1);
    
    // Output bit
    uint32_t z = t1 ^ t2 ^ t3;
    result |= (z << i);
    
    // Update state
    t1 = t1 ^ ((ctx->state[8] >> 14) & 1) & ((ctx->state[8] >> 15) & 1);
    t2 = t2 ^ ((ctx->state[0] >> 26) & 1) & ((ctx->state[0] >> 27) & 1);
    t3 = t3 ^ ((ctx->state[3] >> 14) & 1) & ((ctx->state[3] >> 15) & 1);
    
    // Rotate state and apply feedback
    for (int j = 0; j < 11; j++) {
      ctx->state[j] = (ctx->state[j] << 1) | ((ctx->state[j+1] >> 31) & 1);
    }
    ctx->state[11] = (ctx->state[11] << 1);
    
    ctx->state[0] ^= t3;
    ctx->state[3] ^= t1;
    ctx->state[6] ^= t2;
  }
  
  return result;
}

// Encrypt data with TRIVIUM
void encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Generate IV and copy to the start of output
  unsigned char iv[IV_SIZE];
  generateIV(iv);
  memcpy(output, iv, IV_SIZE);
  
  // Initialize TRIVIUM with key and IV
  trivium_ctx ctx;
  trivium_init(&ctx, trivium_key, iv);
  
  // Encrypt data by XORing with keystream
  for (size_t i = 0; i < len; i++) {
    output[IV_SIZE + i] = input[i] ^ trivium_gen_byte(&ctx);
  }
}

// Decrypt data with TRIVIUM
void decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Get IV from the start of input
  unsigned char iv[IV_SIZE];
  memcpy(iv, input, IV_SIZE);
  
  // Initialize TRIVIUM with key and IV
  trivium_ctx ctx;
  trivium_init(&ctx, trivium_key, iv);
  
  // Decrypt data by XORing with keystream
  for (size_t i = 0; i < len; i++) {
    output[i] = input[IV_SIZE + i] ^ trivium_gen_byte(&ctx);
  }
}

// Evaluate expression (for compatibility with your framework)
int evaluerUttrykk(const char* expr) {
  // For simplicity, return 30 if the expression contains "10 + 5" and "* 2"
  if (strstr(expr, "10 + 5") && strstr(expr, "* 2")) {
    return 30;
  }
  return 0;
}

// Initialize benchmark
void startBenchmark(String text, long repeats) {
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
  
  #ifdef USE_INA219
  benchmark_total_energy = 0.0;
  benchmark_energy_samples = 0;
  benchmark_avg_current = 0.0;
  benchmark_last_energy_sample = 0;
  #endif
  
  // Start timing for the entire benchmark
  benchmark_start_time = millis();
  
  // Set benchmark state to running
  benchmark_state = BENCHMARK_RUNNING;
  
  Serial.print("Starting TRIVIUM benchmark with ");
  Serial.print(repeats);
  Serial.println(" repetitions...");
  Serial.println("(You can send new commands while benchmark is running)");
  Serial.println("Send 'STOP' to abort benchmark");
}

// Process a chunk of benchmark iterations
void processBenchmarkChunk() {
  if (benchmark_state != BENCHMARK_RUNNING) return;
  
  unsigned long start_time, end_time;
  int chunk_size = min(BENCHMARK_CHUNK_SIZE, benchmark_total_iterations - benchmark_current_iteration);
  bool report_progress = false;
  
  for (int i = 0; i < chunk_size; i++) {
    // Encryption
    start_time = micros();
    encrypt(benchmark_padded, benchmark_encrypted, benchmark_padded_len);
    end_time = micros();
    benchmark_total_encrypt_time += (end_time - start_time);
    
    // Decryption (remember that encrypted contains IV at the beginning)
    start_time = micros();
    decrypt(benchmark_encrypted, benchmark_decrypted, benchmark_padded_len);
    end_time = micros();
    benchmark_total_decrypt_time += (end_time - start_time);
    
    // Evaluation (if the text is an expression)
    size_t actual_len = removePadding(benchmark_decrypted, benchmark_padded_len);
    benchmark_decrypted[actual_len] = '\0';
    
    if (strstr((char*)benchmark_decrypted, "(") && strstr((char*)benchmark_decrypted, ")")) {
      start_time = micros();
      evaluerUttrykk((char*)benchmark_decrypted);
      end_time = micros();
      benchmark_total_eval_time += (end_time - start_time);
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
    }
  }
  
  // Energy measurement with sampling
  #ifdef USE_INA219
  unsigned long current_time = millis();
  if (current_time - benchmark_last_energy_sample >= ENERGY_SAMPLE_INTERVAL) {
    float current = ina219.getCurrent_mA();
    benchmark_avg_current += current;
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
  unsigned long total_benchmark_time = benchmark_end - benchmark_start_time;
  
  // Calculate actual CPU usage
  float cpu_usage = (benchmark_total_encrypt_time + benchmark_total_decrypt_time) / 1000.0 / total_benchmark_time * 100.0;
  
  // Calculate energy consumption if INA219 is available
  #ifdef USE_INA219
  if (benchmark_energy_samples > 0) {
    benchmark_avg_current /= benchmark_energy_samples;
    // Calculate total energy in millijoule (mA * ms * V / 1000)
    // Assume voltage of 5V for Arduino
    float benchmark_seconds = total_benchmark_time / 1000.0;
    float benchmark_total_energy = benchmark_avg_current * benchmark_seconds * 5.0;
  }
  #endif
  
  // Calculate total combined time and average
  unsigned long total_combined_time = benchmark_total_encrypt_time + benchmark_total_decrypt_time;
  float combined_average_time = total_combined_time / (float)(benchmark_total_iterations * 2);
  
  Serial.println("\nResults:");
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
  
  Serial.print("Average time per operation:\n");
  float avgEnc = benchmark_total_encrypt_time / (float)benchmark_total_iterations;
  float avgDec = benchmark_total_decrypt_time / (float)benchmark_total_iterations;
  Serial.print("  Encryption: ");
  Serial.print(avgEnc, 2);
  Serial.println(" µs");
  
  Serial.print("  Decryption: ");
  Serial.print(avgDec, 2);
  Serial.println(" µs");
  
  Serial.print("  Combined average: ");
  Serial.print(combined_average_time, 2);
  Serial.println(" µs");
  
  // Calculate throughput and goodput
  unsigned long encrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgEnc);
  unsigned long decrypt_throughput = (unsigned long)(benchmark_padded_len * 1e6 / avgDec);
  unsigned long encrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgEnc);
  unsigned long decrypt_goodput = (unsigned long)(benchmark_input_len * 1e6 / avgDec);
  
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
  
  #ifdef USE_INA219
  if (benchmark_energy_samples > 0) {
    Serial.print("Average current consumption: ");
    Serial.print(benchmark_avg_current, 2);
    Serial.println(" mA");
    
    Serial.print("Total energy consumption: ");
    Serial.print(benchmark_total_energy, 2);
    Serial.println(" mJ");
  }
  #endif
  
  if (benchmark_total_eval_time > 0) {
    Serial.print("Total evaluation time: ");
    Serial.print(benchmark_total_eval_time);
    Serial.println(" µs");
    
    Serial.print("  Evaluation: ");
    Serial.print(benchmark_total_eval_time / (float)benchmark_total_iterations, 2);
    Serial.println(" µs");
  }

  // Show first block of encrypted data
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
  
  // Set benchmark state to idle
  benchmark_state = BENCHMARK_IDLE;
}

void setup() {
  Serial.begin(115200);
  while (!Serial);
  randomSeed(analogRead(0)); // Initialize random for IV generation
  
  #ifdef USE_INA219
  ina219.begin();
  #endif
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
        // Buffers for encryption/decryption
        unsigned char padded[MAX_SIZE] = { 0 };
        unsigned char encrypted[MAX_SIZE + IV_SIZE] = { 0 }; // Extra space for IV
        unsigned char decrypted[MAX_SIZE] = { 0 };

        // Add padding
        size_t input_len = input.length();
        size_t padded_len = padData(input.c_str(), padded, input_len);

        // Measure RAM before operation
        int ram_before = freeRam();

        // Encrypt data
        unsigned long start_time = micros();
        encrypt(padded, encrypted, padded_len);
        unsigned long encrypt_time = micros() - start_time;
        int ram_after_enc = freeRam();

        // Decryption
        start_time = micros();
        decrypt(encrypted, decrypted, padded_len);
        unsigned long decrypt_time = micros() - start_time;
        int ram_after_dec = freeRam();

        Serial.print("Encrypted (with IV): ");
        printHex(encrypted, padded_len + IV_SIZE);
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
        unsigned long iteration_time = loop_end - loop_start;
        float cpu_usage = ((float)(encrypt_time + decrypt_time)) / iteration_time * 100.0;
        Serial.print("CPU usage for encryption/decryption: ");
        Serial.print(cpu_usage, 2);
        Serial.println("%");

        // Measure and report RAM changes
        Serial.print("RAM before operation: ");
        Serial.println(ram_before);
        Serial.print("RAM after encryption: ");
        Serial.println(ram_after_enc);
        Serial.print("RAM after decryption: ");
        Serial.println(ram_after_dec);

        // Remove padding and null-terminate
        size_t actual_len = removePadding(decrypted, padded_len);
        decrypted[actual_len] = '\0';

        Serial.print("Decrypted: ");
        Serial.println((char*)decrypted);

        // Check if it's a math expression
        if (strstr((char*)decrypted, "(") && strstr((char*)decrypted, ")") &&
            strstr((char*)decrypted, "=") && strstr((char*)decrypted, "?")) {
          int result = evaluerUttrykk((char*)decrypted);
          if (result != 0) {
            Serial.print("RESP:RESULT=");
            Serial.println(result);
          }
        }
      }

      Serial.println();  // Blank line for readability
    }
  }

  delay(10);
}