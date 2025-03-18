Python kommunikasjon(laptop/bakkestasjon) ```import socket
import time

# Arduino configuration
ARDUINO_IP = "192.168.1.177"
PORT = 5000


def send_to_arduino(message):
    """Send a message to the Arduino and get the response"""
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5)  # Set a 5-second timeout

    try:
        # Connect to Arduino
        print(f"Connecting to Arduino at {ARDUINO_IP}:{PORT}...")
        client_socket.connect((ARDUINO_IP, PORT))
        print(f"Connected successfully!")

        # Format the message as an HTTP request
        http_request = f"GET /data:{message} HTTP/1.1\r\n"
        http_request += f"Host: {ARDUINO_IP}:{PORT}\r\n"
        http_request += "Connection: close\r\n\r\n"

        # Send the data
        print(f"Sending: '{message}'")
        client_socket.sendall(http_request.encode())

        # Get the response
        print("Waiting for response...")
        response = b""
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                response += data
            except socket.timeout:
                print("Timeout while receiving data")
                break

        # Decode and print the response
        response_str = response.decode('utf-8', errors='replace')
        print("\nResponse from Arduino:")
        print("-" * 40)
        print(response_str)
        print("-" * 40)

        return response_str

    except ConnectionRefusedError:
        print("ERROR: Connection refused. Make sure Arduino is running and the IP/port are correct.")
    except socket.timeout:
        print("ERROR: Connection timed out. Check if the Arduino is powered and the network is working.")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        client_socket.close()
        print("Connection closed")

    return None


def main():
    """Main function with simple menu"""
    print("=" * 50)
    print("Arduino Communication Client")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("1. Send text message to Arduino")
        print("2. Request status from Arduino")
        print("3. Exit")

        choice = input("\nEnter your choice (1-3): ")

        if choice == '1':
            message = input("Enter message to send: ")
            send_to_arduino(message)
        elif choice == '2':
            send_to_arduino("status")
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

        time.sleep(1)


if __name__ == "__main__":
    main()```