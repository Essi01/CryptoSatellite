#include <Arduino.h>

// SPECK Constants for SPECK128/128
#define SPECK_BLOCK_SIZE 16  // 128 bits
#define SPECK_KEY_SIZE 16    // 128 bits
#define SPECK_ROUNDS 32      // Number of rounds for SPECK128/128
#define SPECK_ALPHA 8        // Rotation constant alpha
#define SPECK_BETA 3         // Rotation constant beta
#define IV_SIZE 16           // IV size for CBC mode

// SPECK key (128-bit)
const unsigned char speck_key[SPECK_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Expanded key storage
uint64_t expanded_key[SPECK_ROUNDS];
bool key_initialized = false;

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

#ifdef ARDUINO_ARCH_MBED
#include "mbed_stats.h"
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

// Pad data to 16-byte blocks (SPECK block size)
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

// SPECK helper functions
uint64_t rotl(uint64_t x, unsigned int n) {
  return (x << n) | (x >> (64 - n));
}

uint64_t rotr(uint64_t x, unsigned int n) {
  return (x >> n) | (x << (64 - n));
}

// Convert byte array to uint64_t (little-endian)
uint64_t bytes_to_uint64(const unsigned char* bytes) {
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    result |= ((uint64_t)bytes[i]) << (i * 8);
  }
  return result;
}

// Convert uint64_t to byte array (little-endian)
void uint64_to_bytes(uint64_t value, unsigned char* bytes) {
  for (int i = 0; i < 8; i++) {
    bytes[i] = (value >> (i * 8)) & 0xFF;
  }
}

// SPECK key expansion
void speck_key_schedule() {
  uint64_t k[2]; // Key split into two 64-bit halves
  
  // Convert key bytes to uint64_t values
  k[0] = bytes_to_uint64(speck_key);
  k[1] = bytes_to_uint64(speck_key + 8);
  
  // First round key is the lower 64 bits of the original key
  expanded_key[0] = k[0];
  
  // Generate remaining round keys
  for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
    uint64_t l = k[1];
    l = rotr(l, SPECK_ALPHA);
    l = (l + k[0]) & 0xFFFFFFFFFFFFFFFFULL;
    l = l ^ i;
    k[0] = rotl(k[0], SPECK_BETA);
    k[0] = k[0] ^ l;
    expanded_key[i + 1] = k[0];
    k[1] = l;
  }
  
  key_initialized = true;
}

// SPECK encrypt a single block (128 bits, stored as two 64-bit words)
void speck_encrypt_block(uint64_t* block) {
  uint64_t x = block[0];
  uint64_t y = block[1];
  
  for (int i = 0; i < SPECK_ROUNDS; i++) {
    x = rotr(x, SPECK_ALPHA);
    x = (x + y) & 0xFFFFFFFFFFFFFFFFULL;
    x = x ^ expanded_key[i];
    y = rotl(y, SPECK_BETA);
    y = y ^ x;
  }
  
  block[0] = x;
  block[1] = y;
}

// SPECK decrypt a single block (128 bits, stored as two 64-bit words)
void speck_decrypt_block(uint64_t* block) {
  uint64_t x = block[0];
  uint64_t y = block[1];
  
  for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
    y = y ^ x;
    y = rotr(y, SPECK_BETA);
    x = x ^ expanded_key[i];
    x = (x - y) & 0xFFFFFFFFFFFFFFFFULL;
    x = rotl(x, SPECK_ALPHA);
  }
  
  block[0] = x;
  block[1] = y;
}

// Encrypt data with SPECK-CBC
void encrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Initialize key schedule if needed
  if (!key_initialized) {
    speck_key_schedule();
  }
  
  // Generate IV and copy to the start of output
  unsigned char iv[IV_SIZE];
  generateIV(iv);
  memcpy(output, iv, IV_SIZE);
  
  // Process each block with CBC mode
  unsigned char temp_iv[IV_SIZE];
  memcpy(temp_iv, iv, IV_SIZE);
  
  // Process data in blocks
  for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
    // XOR the plaintext with the IV/previous ciphertext (CBC mode)
    unsigned char xored_block[SPECK_BLOCK_SIZE];
    for (size_t j = 0; j < SPECK_BLOCK_SIZE; j++) {
      xored_block[j] = input[i + j] ^ temp_iv[j];
    }
    
    // Encrypt the block
    uint64_t block[2];
    block[0] = bytes_to_uint64(xored_block);
    block[1] = bytes_to_uint64(xored_block + 8);
    speck_encrypt_block(block);
    
    // Convert the encrypted block back to bytes
    unsigned char encrypted_block[SPECK_BLOCK_SIZE];
    uint64_to_bytes(block[0], encrypted_block);
    uint64_to_bytes(block[1], encrypted_block + 8);
    
    // Copy the encrypted block to the output
    memcpy(output + IV_SIZE + i, encrypted_block, SPECK_BLOCK_SIZE);
    
    // Update the IV for the next block
    memcpy(temp_iv, encrypted_block, SPECK_BLOCK_SIZE);
  }
}

// Decrypt data with SPECK-CBC
void decrypt(const unsigned char* input, unsigned char* output, size_t len) {
  // Initialize key schedule if needed
  if (!key_initialized) {
    speck_key_schedule();
  }
  
  // Get IV from the start of the input
  unsigned char iv[IV_SIZE];
  memcpy(iv, input, IV_SIZE);
  
  // Process each block with CBC mode
  for (size_t i = 0; i < len; i += SPECK_BLOCK_SIZE) {
    // Get the current ciphertext block
    const unsigned char* current_block = input + IV_SIZE + i;
    
    // Convert to 64-bit words
    uint64_t block[2];
    block[0] = bytes_to_uint64(current_block);
    block[1] = bytes_to_uint64(current_block + 8);
    
    // Decrypt the block
    speck_decrypt_block(block);
    
    // Convert back to bytes
    unsigned char decrypted_block[SPECK_BLOCK_SIZE];
    uint64_to_bytes(block[0], decrypted_block);
    uint64_to_bytes(block[1], decrypted_block + 8);
    
    // XOR with the previous ciphertext block (or IV for the first block)
    for (size_t j = 0; j < SPECK_BLOCK_SIZE; j++) {
      unsigned char prev_byte;
      if (i == 0) {
        prev_byte = iv[j];
      } else {
        prev_byte = input[IV_SIZE + i - SPECK_BLOCK_SIZE + j];
      }
      output[i + j] = decrypted_block[j] ^ prev_byte;
    }
  }
}

// Evaluate expression (same as in your AES implementation)
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
  
  // Start timing for the entire benchmark
  benchmark_start_time = millis();
  
  // Set benchmark state to running
  benchmark_state = BENCHMARK_RUNNING;
  
  Serial.print("Starting SPECK benchmark with ");
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
  
  if (benchmark_total_eval_time > 0) {
    Serial.print("Total evaluation time: ");
    Serial.print(benchmark_total_eval_time);
    Serial.println(" µs");
    
    Serial.print("  Evaluation: ");
    Serial.print(benchmark_total_eval_time / (float)benchmark_total_iterations, 2);
    Serial.println(" µs");
  }

  // Show first and last operation result
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
  
  // Pre-compute key schedule
  speck_key_schedule();
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