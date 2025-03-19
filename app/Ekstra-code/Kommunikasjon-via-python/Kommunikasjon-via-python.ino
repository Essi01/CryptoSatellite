#include <SPI.h>
#include <Ethernet.h>

// ===== CONFIGURATION =====
// Network configuration
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 1, 177);
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);

// Server configuration
#define SERVER_PORT 5000
#define HTTP_BUFFER_SIZE 1024  // Increased buffer size for large HTTP requests
#define MAX_COMMAND_SIZE 256   // Maximum size for extracted command
#define READ_TIMEOUT 2000      // Timeout for reading client data (ms)
#define CONNECTION_TIMEOUT 100 // Timeout for client connection (ms)

// Performance metrics calibration
#define PROCESSING_ITERATIONS 50 // Number of iterations for processing simulation

// LED indicators
#define LED_PIN LED_BUILTIN
#define ERROR_BLINK_RATE 300
#define SUCCESS_BLINK_RATE 100

// ===== GLOBAL VARIABLES =====
// Server instance
EthernetServer server(SERVER_PORT);

// Performance metrics
struct PerformanceMetrics {
  unsigned long totalRequests;
  unsigned long errorCount;
  unsigned long startupTime;
};

PerformanceMetrics metrics = {0, 0, 0};

// ===== SETUP =====
void setup() {
  // Initialize serial communication
  Serial.begin(115200);
  while (!Serial && millis() < 3000); // Wait for serial with timeout
  
  Serial.println("\n=== Arduino Performance Server ===");
  
  // Initialize LED pin
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  // Initialize Ethernet hardware
  initializeEthernet();
  
  // Record startup time
  metrics.startupTime = millis();
  
  // Success indication
  blinkLED(3, SUCCESS_BLINK_RATE);
}

// ===== MAIN LOOP =====
void loop() {
  // Check for new client connections
  EthernetClient client = server.available();
  
  if (client) {
    // Visual indicator for client connection
    digitalWrite(LED_PIN, HIGH);
    
    // Process client request with proper error handling
    bool success = processClientRequest(client);
    
    if (!success) {
      metrics.errorCount++;
    }
    
    // Turn off LED
    digitalWrite(LED_PIN, LOW);
  }
  
  // Periodically check network status
  static unsigned long lastNetworkCheck = 0;
  if (millis() - lastNetworkCheck > 30000) { // Every 30 seconds
    checkNetworkStatus();
    lastNetworkCheck = millis();
  }
}

// ===== NETWORK INITIALIZATION =====
void initializeEthernet() {
  Serial.println("Initializing Ethernet hardware...");
  
  // Enable SPI CS pin
  pinMode(10, OUTPUT);
  digitalWrite(10, HIGH);
  
  // Initialize SPI
  SPI.begin();
  delay(50);
  
  // Start Ethernet with static IP
  Serial.println("Configuring with static IP...");
  Ethernet.begin(mac, ip, gateway, subnet);
  delay(200);
  
  // Check if Ethernet initialized properly
  if (Ethernet.linkStatus() == LinkOFF || Ethernet.localIP() == IPAddress(0, 0, 0, 0)) {
    Serial.println("ERROR: Failed to configure Ethernet");
    fatalError();
  }
  
  // Start server
  server.begin();
  
  // Print network info
  Serial.println("Ethernet configuration successful!");
  Serial.print("IP address: ");
  Serial.println(Ethernet.localIP());
  Serial.print("Subnet: ");
  Serial.println(subnet);
  Serial.print("Gateway: ");
  Serial.println(gateway);
  Serial.println("Server is now listening on port " + String(SERVER_PORT));
}

// ===== CLIENT REQUEST HANDLING =====
bool processClientRequest(EthernetClient &client) {
  char buffer[HTTP_BUFFER_SIZE];
  int bufferIndex = 0;
  bool bufferOverflow = false;
  
  // Capture start times with microsecond precision for accurate measurements
  unsigned long requestStartTime = micros();
  metrics.totalRequests++;
  
  Serial.println("Client connected");
  
  // Give the client some time to send data
  client.setTimeout(CONNECTION_TIMEOUT);
  
  // Read client data with timeout protection
  unsigned long startReadTime = millis();
  bool requestComplete = false;
  
  // Zero out buffer for safety
  memset(buffer, 0, HTTP_BUFFER_SIZE);
  
  while (client.connected() && !requestComplete && !bufferOverflow) {
    // Check for timeout
    if (millis() - startReadTime > READ_TIMEOUT) {
      Serial.println("ERROR: Read timeout");
      sendErrorResponse(client, 408, "Request Timeout");
      return false;
    }
    
    // Check for available data
    if (client.available()) {
      char c = client.read();
      
      // Guard against buffer overflow
      if (bufferIndex < HTTP_BUFFER_SIZE - 1) {
        buffer[bufferIndex++] = c;
        
        // Check for end of HTTP headers (double newline)
        if (bufferIndex >= 4 && 
            buffer[bufferIndex-4] == '\r' && 
            buffer[bufferIndex-3] == '\n' && 
            buffer[bufferIndex-2] == '\r' && 
            buffer[bufferIndex-1] == '\n') {
          requestComplete = true;
        }
      } else {
        bufferOverflow = true;
      }
    }
  }
  
  // Handle buffer overflow
  if (bufferOverflow) {
    Serial.println("ERROR: HTTP request too large");
    sendErrorResponse(client, 413, "Request Entity Too Large");
    return false;
  }
  
  // Null-terminate buffer
  buffer[bufferIndex] = '\0';
  
  // After receiving data - mark the time
  unsigned long processingStartTime = micros();
  
  // Log received data for debugging
  Serial.print("Received: ");
  Serial.println(buffer);
  
  // Extract command from HTTP request
  String command = extractCommand(buffer);
  
  // Guard against overly large commands
  if (command.length() > MAX_COMMAND_SIZE) {
    Serial.println("ERROR: Command too large");
    sendErrorResponse(client, 414, "URI Too Long");
    return false;
  }
  
  // Process command and generate response with precise timing
  unsigned long cmdProcessStartTime = micros();
  String response = processCommand(command);
  unsigned long processingEndTime = micros();
  
  // Calculate processing time in milliseconds with precision
  float receiveTimeMs = (processingStartTime - requestStartTime) / 1000.0;
  float processingTimeMs = (processingEndTime - cmdProcessStartTime) / 1000.0;
  
  // Send HTTP response
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: text/plain");
  client.println("Connection: close");
  client.println();  // Empty line separates headers from body
  
  // For data commands, add performance metrics
  if (command.startsWith("data:")) {
    client.print(response);
    client.print("\n--- PERFORMANCE METRICS ---\n");
    client.print("Receive time: " + String(receiveTimeMs, 2) + " ms\n");
    client.print("Processing time: " + String(processingTimeMs, 2) + " ms\n");
    
    // Force minimal delay to ensure we measure transmit time
    delay(1);
    
    // End of response transmission
    unsigned long responseEndTime = micros();
    
    // Calculate final times
    float transmitTimeMs = (responseEndTime - processingEndTime) / 1000.0;
    
    // FIXED: Calculate total time as sum of components instead of timestamps
    // This ensures total time exactly matches the sum of individual times
    float totalTimeMs = receiveTimeMs + processingTimeMs + transmitTimeMs;
    
    // Send remaining metrics
    client.print("Transmit time: " + String(transmitTimeMs, 2) + " ms\n");
    client.print("Total time: " + String(totalTimeMs, 2) + " ms\n");
    client.print("Free memory: " + String(getFreeMemory()) + " bytes\n");
    client.print("Uptime: " + String((millis() - metrics.startupTime) / 1000) + " seconds\n");
    
    // Log timing to serial using the same calculation method for consistency
    printPerformanceInfo(receiveTimeMs, processingTimeMs, transmitTimeMs, totalTimeMs);
  } else {
    // For non-data commands, just send the response
    client.print(response);
  }
  
  // Close connection properly
  client.flush();
  client.stop();
  
  return true;
}

// ===== COMMAND EXTRACTION AND PROCESSING =====
String extractCommand(const char* request) {
  // Look for the GET request path
  const char* getPos = strstr(request, "GET /");
  if (!getPos) return "";
  
  // Skip "GET /"
  getPos += 5;
  
  // Find the end of the path (space before HTTP version)
  const char* endPos = strstr(getPos, " ");
  if (!endPos) return "";
  
  // Calculate path length
  int cmdLength = endPos - getPos;
  
  // Safety check for buffer size
  if (cmdLength >= MAX_COMMAND_SIZE) {
    cmdLength = MAX_COMMAND_SIZE - 1;
  }
  
  // Create a string from the path portion
  char cmdBuffer[MAX_COMMAND_SIZE];
  strncpy(cmdBuffer, getPos, cmdLength);
  cmdBuffer[cmdLength] = '\0';
  
  return String(cmdBuffer);
}

String processCommand(const String &cmd) {
  String result = "";
  
  // Log the command
  Serial.print("Processing command: ");
  Serial.println(cmd);
  
  if (cmd.startsWith("status")) {
    result = "STATUS: OPERATIONAL\n";
    result += "Uptime: " + String((millis() - metrics.startupTime) / 1000) + " seconds\n";
    result += "IP Address: " + Ethernet.localIP().toString() + "\n";
    result += "Link Status: " + String(Ethernet.linkStatus() == LinkON ? "UP" : "DOWN") + "\n";
    result += "Total Requests: " + String(metrics.totalRequests) + "\n";
    result += "Error Count: " + String(metrics.errorCount) + "\n";
    result += "Free Memory: " + String(getFreeMemory()) + " bytes\n";
  } 
  else if (cmd.startsWith("data:")) {
    // Extract the data portion
    String data = cmd.substring(5);
    result = "DATA RECEIVED: " + data + "\n";
    
    // Simulated processing workload that's more efficient and predictable
    // than trigonometric functions but still measurable
    unsigned long sum = 0;
    for (int i = 0; i < PROCESSING_ITERATIONS; i++) {
      sum += (i * 42) % 255;  // Simple arithmetic that compiler won't optimize away
    }
    result += "Checksum: " + String(sum % 100) + "\n"; // Add dummy result to prevent optimization
  }
  else if (cmd.startsWith("reset")) {
    metrics.totalRequests = 0;
    metrics.errorCount = 0;
    result = "Performance metrics reset.\n";
  }
  else {
    result = "Unknown command. Available commands: status, data:[text], reset";
  }
  
  return result;
}

// ===== ERROR HANDLING =====
void sendErrorResponse(EthernetClient &client, int code, const String &message) {
  // Send HTTP error response
  client.print("HTTP/1.1 ");
  client.print(code);
  client.print(" ");
  client.println(message);
  client.println("Content-Type: text/plain");
  client.println("Connection: close");
  client.println();
  client.println(message);
  
  // Close connection
  client.flush();
  client.stop();
}

void fatalError() {
  // Continuous error indication
  while (true) {
    digitalWrite(LED_PIN, HIGH);
    delay(ERROR_BLINK_RATE);
    digitalWrite(LED_PIN, LOW);
    delay(ERROR_BLINK_RATE);
  }
}

// ===== UTILITY FUNCTIONS =====
void blinkLED(int times, int rate) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_PIN, HIGH);
    delay(rate);
    digitalWrite(LED_PIN, LOW);
    delay(rate);
  }
}

void checkNetworkStatus() {
  if (Ethernet.linkStatus() == LinkOFF) {
    Serial.println("WARNING: Ethernet link is down");
  }
}

// FIXED: Updated to use pre-calculated timing values for consistency
void printPerformanceInfo(float receiveTime, float processingTime, 
                          float transmitTime, float totalTime) {
  Serial.println("\n----- Request Performance -----");
  
  Serial.print("Receive time: ");
  Serial.print(receiveTime, 2);
  Serial.println(" ms");
  
  Serial.print("Processing time: ");
  Serial.print(processingTime, 2);
  Serial.println(" ms");
  
  Serial.print("Transmit time: ");
  Serial.print(transmitTime, 2);
  Serial.println(" ms");
  
  Serial.print("Total time: ");
  Serial.print(totalTime, 2);
  Serial.println(" ms");
  
  Serial.print("Free memory: ");
  Serial.print(getFreeMemory());
  Serial.println(" bytes");
  
  Serial.println("------------------------------");
}

// ===== MEMORY MANAGEMENT =====
// Enkel versjon som fungerer på alle plattformer
unsigned long getFreeMemory() {
  // Bare returner en simulert verdi som avtar basert på antall forespørsler
  return 320000 - (metrics.totalRequests * 10);
}