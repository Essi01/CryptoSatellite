import socket
import time
import re
import json
import logging
from datetime import datetime
import argparse
import sys
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
import threading

# Optional imports - handle gracefully if not available
try:
    import matplotlib.pyplot as plt
    import numpy as np

    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False
    print("WARNING: Matplotlib not available. Plotting features disabled.")

# =========================== CONFIGURATION ===========================
DEFAULT_CONFIG = {
    "arduino_ip": "192.168.1.177",
    "port": 5000,
    "timeout": 3,  # Socket timeout in seconds
    "log_level": "INFO",
    "retry_count": 3,
    "retry_delay": 1.0,  # Seconds
    "auto_reconnect": True,
    "plot_update_interval": 1.0,  # Seconds
    "plot_history_size": 20,  # Number of data points to keep
}


# =========================== LOGGING SETUP ===========================
def setup_logging(level: str = "INFO") -> logging.Logger:
    """Initialize logging with appropriate format and level"""
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=getattr(logging, level), format=log_format)
    return logging.getLogger("arduino_monitor")


logger = setup_logging(DEFAULT_CONFIG["log_level"])


# =========================== DATA STRUCTURES ===========================
@dataclass
class PerformanceMetrics:
    """Store performance metrics data"""
    timestamp: List[datetime] = field(default_factory=list)
    total_time: List[float] = field(default_factory=list)
    receive_time: List[float] = field(default_factory=list)
    processing_time: List[float] = field(default_factory=list)
    transmit_time: List[float] = field(default_factory=list)
    total_arduino_time: List[float] = field(default_factory=list)
    message_size: List[int] = field(default_factory=list)
    free_memory: List[int] = field(default_factory=list)

    def reset(self) -> None:
        """Clear all stored metrics"""
        for attr in self.__dict__:
            setattr(self, attr, [])

    def add_measurement(self, **kwargs) -> None:
        """Add a new measurement to each list"""
        self.timestamp.append(kwargs.get('timestamp', datetime.now()))
        self.total_time.append(kwargs.get('total_time', 0))
        self.receive_time.append(kwargs.get('receive_time', 0))
        self.processing_time.append(kwargs.get('processing_time', 0))
        self.transmit_time.append(kwargs.get('transmit_time', 0))

        # Calculate total Arduino time
        arduino_time = kwargs.get('total_arduino_time', None)
        if arduino_time is None and all(k in kwargs for k in ['receive_time', 'processing_time', 'transmit_time']):
            arduino_time = kwargs['receive_time'] + kwargs['processing_time'] + kwargs['transmit_time']

        self.total_arduino_time.append(arduino_time or 0)
        self.message_size.append(kwargs.get('message_size', 0))
        self.free_memory.append(kwargs.get('free_memory', 0))


# Global metrics storage
metrics = PerformanceMetrics()


# =========================== COMMUNICATION ===========================
class ArduinoClient:
    """Handle communication with Arduino over TCP/IP"""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize with configuration parameters"""
        self.config = config
        self.connected = False
        self.socket = None
        self._lock = threading.Lock()  # Thread safety for socket operations

    def connect(self) -> bool:
        """Establish a connection to the Arduino"""
        if self.connected:
            return True

        try:
            with self._lock:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.config["timeout"])
                self.socket.connect((self.config["arduino_ip"], self.config["port"]))
                self.connected = True

            logger.info(f"Connected to Arduino at {self.config['arduino_ip']}:{self.config['port']}")
            return True

        except ConnectionRefusedError:
            logger.error("Connection refused. Check if Arduino is running.")
        except socket.timeout:
            logger.error("Connection timed out. Check network and Arduino.")
        except socket.error as e:
            logger.error(f"Socket error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        self.connected = False
        return False

    def disconnect(self) -> None:
        """Close the connection to Arduino"""
        with self._lock:
            if self.socket:
                try:
                    self.socket.close()
                except Exception as e:
                    logger.warning(f"Error closing socket: {e}")
                finally:
                    self.socket = None
                    self.connected = False

    def send_message(self, message: str, collect_stats: bool = True) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Send a message to Arduino and get response with timing data

        Args:
            message: Message to send
            collect_stats: Whether to store metrics

        Returns:
            Tuple of (response text, timing metrics dictionary)
        """
        metrics_data = {
            'timestamp': datetime.now(),
            'total_time': 0,
            'message_size': 0
        }

        # Try multiple times according to retry policy
        for attempt in range(self.config["retry_count"]):
            if attempt > 0:
                logger.info(f"Retry attempt {attempt + 1}/{self.config['retry_count']}...")
                time.sleep(self.config["retry_delay"])

            start_time = time.time()

            # Ensure we're connected
            if not self.connected and not self.connect():
                continue  # Try next attempt if connection failed

            try:
                with self._lock:
                    # Create HTTP request
                    http_request = f"GET /data:{message} HTTP/1.1\r\n"
                    http_request += f"Host: {self.config['arduino_ip']}:{self.config['port']}\r\n"
                    http_request += "Connection: close\r\n\r\n"

                    request_size = len(http_request)
                    metrics_data['message_size'] = request_size

                    logger.debug(f"Sending request ({request_size} bytes)")
                    self.socket.sendall(http_request.encode())

                    # Receive response
                    response_data = self._receive_all()

                # Calculate total time
                end_time = time.time()
                metrics_data['total_time'] = (end_time - start_time) * 1000  # Convert to ms

                # Decode response
                response = response_data.decode('utf-8', errors='replace')

                # Parse Arduino metrics
                arduino_metrics = self._extract_metrics(response)
                metrics_data.update(arduino_metrics)

                # Calculate network overhead if we have Arduino time
                if 'total_arduino_time' in metrics_data and metrics_data['total_arduino_time'] > 0:
                    metrics_data['network_overhead'] = metrics_data['total_time'] - metrics_data['total_arduino_time']

                # Store metrics if needed
                if collect_stats:
                    metrics.add_measurement(**metrics_data)

                # Always disconnect after successful communication
                self.disconnect()

                return response, metrics_data

            except socket.timeout:
                logger.warning("Socket timeout during communication")
                self.disconnect()
            except socket.error as e:
                logger.error(f"Socket error: {e}")
                self.disconnect()
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                self.disconnect()

        # If we get here, all attempts failed
        logger.error(f"Failed to communicate after {self.config['retry_count']} attempts")
        return None, metrics_data

    def _receive_all(self) -> bytes:
        """Receive all data from socket until connection closes"""
        buffer = b""
        self.socket.settimeout(self.config["timeout"])

        while True:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                buffer += chunk
            except socket.timeout:
                logger.warning("Timeout while receiving data")
                break

        return buffer

    def _extract_metrics(self, response: str) -> Dict[str, float]:
        """
        Extract performance metrics from Arduino response

        Returns dictionary with extracted values
        """
        metrics_dict = {
            'receive_time': 0,
            'processing_time': 0,
            'transmit_time': 0,
            'total_arduino_time': 0,
            'free_memory': 0
        }

        # Check if response contains metrics section
        if "--- PERFORMANCE METRICS ---" not in response:
            return metrics_dict

        try:
            # Process line by line after the metrics header
            in_metrics = False
            for line in response.split('\n'):
                line = line.strip()

                if "--- PERFORMANCE METRICS ---" in line:
                    in_metrics = True
                    continue

                if not in_metrics or ":" not in line:
                    continue

                # Split into key and value
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip().lower().replace(" ", "_")
                value_part = parts[1].strip()

                # Extract numeric value - handle both integers and floats
                # Use regex to find the number pattern
                number_match = re.search(r'([\d.]+)', value_part)
                if not number_match:
                    continue

                try:
                    # Convert to appropriate numeric type
                    value_str = number_match.group(1)
                    value = float(value_str) if '.' in value_str else int(value_str)

                    # Store in appropriate metric
                    if key == 'free_memory':
                        metrics_dict['free_memory'] = value
                    elif key == 'receive_time':
                        metrics_dict['receive_time'] = value
                    elif key == 'processing_time':
                        metrics_dict['processing_time'] = value
                    elif key == 'transmit_time':
                        metrics_dict['transmit_time'] = value
                    elif key == 'total_time':
                        metrics_dict['total_arduino_time'] = value
                except ValueError:
                    logger.debug(f"Could not convert value: {value_part}")

        except Exception as e:
            logger.error(f"Error extracting metrics: {e}")

        return metrics_dict


# =========================== OUTPUT FORMATTING ===========================
def format_response(response: str, timing_data: Dict[str, Any], message_size: int) -> str:
    """Format the response and timing data for display"""
    output = "\n" + "=" * 60 + "\n"
    output += "RESPONSE DETAILS\n"
    output += "-" * 60 + "\n\n"

    # Timing information
    output += f"Total round-trip time: {timing_data.get('total_time', 0):.2f} ms\n"

    # Arduino timing if available
    if any(timing_data.get(k, 0) for k in ['receive_time', 'processing_time', 'transmit_time']):
        output += "Arduino timing breakdown:\n"

        if timing_data.get('receive_time', 0) > 0:
            output += f"  ├─ Receive time: {timing_data['receive_time']:.2f} ms\n"

        if timing_data.get('processing_time', 0) > 0:
            output += f"  ├─ Processing time: {timing_data['processing_time']:.2f} ms\n"

        if timing_data.get('transmit_time', 0) > 0:
            output += f"  ├─ Transmit time: {timing_data['transmit_time']:.2f} ms\n"

        # Calculate and show total Arduino time
        arduino_total = sum(timing_data.get(k, 0) for k in ['receive_time', 'processing_time', 'transmit_time'])
        output += f"  └─ Total Arduino time: {arduino_total:.2f} ms\n"

        # Network overhead
        if arduino_total > 0 and arduino_total < timing_data.get('total_time', 0):
            overhead = timing_data['total_time'] - arduino_total
            overhead_percent = (overhead / timing_data['total_time']) * 100
            output += f"Network overhead: {overhead:.2f} ms ({overhead_percent:.1f}%)\n"

    # Memory information
    if timing_data.get('free_memory', 0) > 0:
        output += f"Free memory: {timing_data['free_memory']} bytes\n"

    output += f"Message size: {message_size} bytes\n\n"

    # Extract and display response body
    if "\r\n\r\n" in response:
        body = response.split("\r\n\r\n", 1)[1]
        output += "Response from Arduino:\n"
        output += "-" * 60 + "\n"
        output += body
    else:
        output += "Response from Arduino:\n"
        output += "-" * 60 + "\n"
        output += response

    output += "\n" + "=" * 60

    return output


def print_statistics() -> None:
    """Display statistics about collected measurements"""
    if not metrics.total_time:
        print("No measurements have been collected yet.")
        return

    print("\n" + "=" * 60)
    print("COMMUNICATION STATISTICS")
    print("-" * 60)

    # Helper function for statistics
    def print_metric_stats(name, values, unit="", precision=2):
        filtered = [v for v in values if v > 0]
        if not filtered:
            return

        print(f"\n{name}:")
        print(f"  Min: {min(filtered):.{precision}f}{unit}")
        print(f"  Max: {max(filtered):.{precision}f}{unit}")
        print(f"  Avg: {sum(filtered) / len(filtered):.{precision}f}{unit}")
        if len(filtered) > 1:
            variance = sum((x - (sum(filtered) / len(filtered))) ** 2 for x in filtered) / len(filtered)
            std_dev = variance ** 0.5
            print(f"  Std Dev: {std_dev:.{precision}f}{unit}")

    # Total time statistics
    print_metric_stats("Total Round-Trip Time", metrics.total_time, " ms")

    # Arduino timing statistics
    print_metric_stats("Arduino Receive Time", metrics.receive_time, " ms")
    print_metric_stats("Arduino Processing Time", metrics.processing_time, " ms")
    print_metric_stats("Arduino Transmit Time", metrics.transmit_time, " ms")
    print_metric_stats("Total Arduino Time", metrics.total_arduino_time, " ms")

    # Calculate network overhead
    if metrics.total_time and metrics.total_arduino_time:
        network_overhead = [t - a for t, a in zip(metrics.total_time, metrics.total_arduino_time)
                            if t > 0 and a > 0 and t > a]
        if network_overhead:
            print_metric_stats("Network Overhead", network_overhead, " ms")

    # Memory statistics if available
    if any(metrics.free_memory):
        print_metric_stats("Free Memory", metrics.free_memory, " bytes", 0)

    # Percentages if we have all components
    if (metrics.receive_time and metrics.processing_time and
            metrics.transmit_time and metrics.total_arduino_time):

        avg_receive = sum(metrics.receive_time) / len(metrics.receive_time)
        avg_processing = sum(metrics.processing_time) / len(metrics.processing_time)
        avg_transmit = sum(metrics.transmit_time) / len(metrics.transmit_time)
        avg_total = sum(metrics.total_arduino_time) / len(metrics.total_arduino_time)

        if avg_total > 0:
            print("\nTime Distribution:")
            print(f"  Receive: {(avg_receive / avg_total) * 100:.1f}%")
            print(f"  Processing: {(avg_processing / avg_total) * 100:.1f}%")
            print(f"  Transmit: {(avg_transmit / avg_total) * 100:.1f}%")

    print("=" * 60)


# =========================== VISUALIZATION ===========================
def plot_measurements() -> None:
    """Create plots of collected measurements"""
    if not HAS_PLOTTING:
        print("ERROR: Matplotlib is not installed. Cannot plot measurements.")
        print("Install with: pip install matplotlib")
        return

    if not metrics.timestamp:
        print("No data to plot.")
        return

    try:
        # Create figure with subplots
        fig, axs = plt.subplots(3, 1, figsize=(12, 10))
        fig.suptitle('Arduino Communication Performance', fontsize=16)

        # Plot timing data - primary subplot
        axs[0].plot(metrics.timestamp, metrics.total_time, 'b-o', linewidth=2, label='Total Round-trip Time')

        # Plot Arduino timing components if available
        if any(metrics.receive_time):
            axs[0].plot(metrics.timestamp, metrics.receive_time, 'g-o', label='Receive Time')

        if any(metrics.processing_time):
            axs[0].plot(metrics.timestamp, metrics.processing_time, 'r-o', label='Processing Time')

        if any(metrics.transmit_time):
            axs[0].plot(metrics.timestamp, metrics.transmit_time, 'c-o', label='Transmit Time')

        if any(metrics.total_arduino_time):
            axs[0].plot(metrics.timestamp, metrics.total_arduino_time, 'm-o',
                        linewidth=2, label='Total Arduino Time')

        axs[0].set_ylabel('Time (ms)')
        axs[0].set_title('Response Time Analysis')
        axs[0].legend(loc='upper left')
        axs[0].grid(True, alpha=0.3)

        # Calculate and plot network overhead if available
        if metrics.total_time and metrics.total_arduino_time:
            network_overhead = []
            valid_indices = []

            for i, (t, a) in enumerate(zip(metrics.total_time, metrics.total_arduino_time)):
                if t > 0 and a > 0 and t > a:
                    network_overhead.append(t - a)
                    valid_indices.append(i)

            if network_overhead:
                overhead_times = [metrics.timestamp[i] for i in valid_indices]
                axs[1].plot(overhead_times, network_overhead, 'r-o', linewidth=2)
                axs[1].set_ylabel('Time (ms)')
                axs[1].set_title('Network Overhead')
                axs[1].grid(True, alpha=0.3)
        else:
            # If no overhead data, plot message size instead
            axs[1].plot(metrics.timestamp, metrics.message_size, 'm-o')
            axs[1].set_ylabel('Message Size (bytes)')
            axs[1].set_title('Message Size')
            axs[1].grid(True, alpha=0.3)

        # Plot memory usage if available
        if any(metrics.free_memory):
            axs[2].plot(metrics.timestamp, metrics.free_memory, 'g-o', linewidth=2)
            axs[2].set_ylabel('Memory (bytes)')
            axs[2].set_title('Free Memory')
            axs[2].grid(True, alpha=0.3)
        else:
            # Hide the unused subplot
            axs[2].set_visible(False)

        # Format x-axis dates
        for ax in axs:
            if ax.get_visible():
                plt.sca(ax)
                plt.xticks(rotation=45)
                plt.tight_layout()

        # Layout adjustments
        plt.subplots_adjust(top=0.92, hspace=0.3)

        # Save plot if possible
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"arduino_performance_{timestamp}.png"
            plt.savefig(filename, dpi=300)
            print(f"Plot saved as {filename}")
        except Exception as e:
            logger.warning(f"Could not save plot: {e}")

        # Show plot
        plt.show()

    except Exception as e:
        logger.error(f"Error creating plot: {e}")
        print(f"Error creating plot: {e}")


# =========================== BENCHMARK FUNCTIONS ===========================
def run_benchmark(client: ArduinoClient, message_count: int = 5, message_size: int = 100) -> None:
    """
    Run a benchmark with multiple messages

    Args:
        client: ArduinoClient instance
        message_count: Number of messages to send
        message_size: Size of each message in bytes
    """
    print(f"\nRunning benchmark with {message_count} messages of {message_size} bytes each")

    # Create test message of specified size
    test_message = "A" * message_size

    # Run multiple iterations
    success_count = 0

    for i in range(message_count):
        print(f"\n--- Test {i + 1}/{message_count} ---")

        # Send the message
        response, timing_data = client.send_message(test_message)

        if response:
            success_count += 1

        # Wait briefly between messages
        if i < message_count - 1:
            time.sleep(0.5)

    # Print results
    print(f"\nBenchmark complete: {success_count}/{message_count} messages successful")

    # Show statistics
    print_statistics()


def reset_metrics(client: ArduinoClient) -> None:
    """Reset metrics on Arduino and clear local measurements"""
    print("\nResetting all metrics...")

    # Reset Arduino metrics
    client.send_message("reset", collect_stats=False)

    # Clear local measurements
    metrics.reset()

    print("All metrics have been reset.")


# =========================== MAIN INTERFACE ===========================
def interactive_mode(client: ArduinoClient) -> None:
    """Run the interactive menu interface"""
    print("=" * 60)
    print("Arduino Communication Performance Monitor")
    print("=" * 60)
    print(f"Target: {client.config['arduino_ip']}:{client.config['port']}")

    while True:
        print("\nOptions:")
        print("1. Send message to Arduino")
        print("2. Request Arduino status")
        print("3. Run benchmark test")
        print("4. Show statistics")
        print("5. Plot measurements")
        print("6. Reset all metrics")
        print("7. Exit program")

        try:
            choice = input("\nSelect an option (1-7): ")

            if choice == '1':
                message = input("Enter message to send: ")
                response, timing_data = client.send_message(message)
                if response:
                    print(format_response(response, timing_data, timing_data.get('message_size', 0)))

            elif choice == '2':
                response, timing_data = client.send_message("status", collect_stats=False)
                if response:
                    print(format_response(response, timing_data, timing_data.get('message_size', 0)))

            elif choice == '3':
                try:
                    count = int(input("Number of messages (default 5): ") or "5")
                    size = int(input("Message size in bytes (default 100): ") or "100")
                    run_benchmark(client, count, size)
                except ValueError:
                    logger.error("Invalid input. Using default values.")
                    run_benchmark(client)

            elif choice == '4':
                print_statistics()

            elif choice == '5':
                plot_measurements()

            elif choice == '6':
                reset_metrics(client)

            elif choice == '7':
                print("Exiting program.")
                break

            else:
                print("Invalid option. Please select a number from 1 to 7.")

        except KeyboardInterrupt:
            print("\nProgram interrupted.")
            break
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            print(f"An error occurred: {e}")


def main() -> None:
    """Main entry point"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Arduino Performance Monitor")
    parser.add_argument("--ip", help="Arduino IP address", default=DEFAULT_CONFIG["arduino_ip"])
    parser.add_argument("--port", type=int, help="Arduino port", default=DEFAULT_CONFIG["port"])
    parser.add_argument("--timeout", type=float, help="Socket timeout in seconds", default=DEFAULT_CONFIG["timeout"])
    parser.add_argument("--log", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level", default=DEFAULT_CONFIG["log_level"])
    parser.add_argument("--message", help="Send a single message and exit")
    parser.add_argument("--status", action="store_true", help="Request status and exit")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark and exit")

    args = parser.parse_args()

    # Update configuration
    config = DEFAULT_CONFIG.copy()
    config["arduino_ip"] = args.ip
    config["port"] = args.port
    config["timeout"] = args.timeout
    config["log_level"] = args.log

    # Set up logging
    global logger
    logger = setup_logging(config["log_level"])

    # Create client
    client = ArduinoClient(config)

    # Handle command-line operations
    if args.status:
        response, timing_data = client.send_message("status", collect_stats=False)
        if response:
            print(format_response(response, timing_data, timing_data.get('message_size', 0)))
        sys.exit(0)

    if args.message:
        response, timing_data = client.send_message(args.message)
        if response:
            print(format_response(response, timing_data, timing_data.get('message_size', 0)))
        sys.exit(0)

    if args.benchmark:
        run_benchmark(client)
        sys.exit(0)

    # Default to interactive mode
    try:
        interactive_mode(client)
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()