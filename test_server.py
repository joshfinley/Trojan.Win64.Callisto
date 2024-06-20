import socket
import threading

# Command definitions matching the client
CMD_NULL = 0b0000
CMD_HELLO = 0b0001
CMD_READY = 0b0010
CMD_EXEC = 0b0100
CMD_EXIT = 0b1000
CIPHER_KEY = 0xFF  # Example cipher key for XOR
BUFFER_SIZE = 1024

# Hardcoded command
command_to_send = 'cmd.exe /c copy /b NUL %TEMP%\\test.txt\0'

def xor_cipher(data, key):
    return bytes([b ^ key for b in data])

def handle_client(client_socket):
    try:
        # Step 2: Await client hello
        client_hello = client_socket.recv(1)
        if not client_hello or client_hello[0] != CMD_HELLO:
            print("Expected client hello, got something else or nothing.")
            client_socket.close()
            return
        
        # Step 3: Send server hello
        client_socket.sendall(bytes([CMD_HELLO]))
        print("Sent server hello")

        # Step 4: Wait for client ready signal
        client_ready = client_socket.recv(1)
        if not client_ready or client_ready[0] != CMD_READY:
            print("Expected client ready, got something else or nothing.")
            client_socket.close()
            return
        print("Received client ready")

        # Send server ready
        client_socket.sendall(bytes([CMD_READY]))
        print("Sent server ready")

        # Send command key
        client_socket.sendall(bytes([CMD_EXEC]))

        # Step 5: Send cipher key
        client_socket.sendall(bytes([CIPHER_KEY]))
        print("Sent cipher key")

        # Step 6: Send ciphered command
        encrypted_command = xor_cipher(command_to_send.encode('utf-8'), CIPHER_KEY)
        client_socket.sendall(encrypted_command)
        print("Sent ciphered command")

        # Step 7: Receive command output
        output = client_socket.recv(BUFFER_SIZE)
        if not output:
            print("Warning: Received empty output from client.")
        else:
            print("Received command output:", output.decode('utf-8'))

    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        client_socket.close()

def start_server(server_ip, server_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen(5)
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server("0.0.0.0", 1664)
