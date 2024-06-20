ifndef _winsock_inc
_winsock_inc equ <1>

;
; Constants
;

; Socket constants
sock_stream equ 1
af_inet     equ 2
sock_raw    equ 3
ipproto_tcp equ 6

socket_error    equ -1
msg_waitall     equ 8

; WSA constants
wsadescription_len  equ 256
wsasys_status_len   equ 128
sd_recv             equ 0
sd_send             equ 1
sd_both             equ 2
sol_socket          equ 0xffff
so_rcvtimeo         equ 0x1006
wsatimedout         equ 0x10060

;
; Function prototypes
; 
WSACleanup          proto
WSAGetLastError     proto
htons               proto :word
closesocket         proto :dword
inet_addr           proto :qword
inet_pton           proto :qword
WSAStartup          proto :word, :qword
shutdown            proto :dword, :dword
socket              proto :dword, :dword, :dword
connect             proto :dword, :qword, :dword
send                proto :dword, :qword, :dword, :dword
recv                proto :dword, :qword, :dword, :dword
getaddrinfo         proto :qword, :qword, :qword, :qword
setsockopt          proto :dword, :dword, :dword, :qword, :dword

;
; Structures
;
wsadata struct
    wVersion        word ?
    wHighVersion    word ?
    iMaxSockets     word ?
    iMaxUdpDg       word ?
    lpVendorInfo    byte ?
    szDescription   byte 256 dup(?), ?
    szSystemStatus  byte 128 dup(?), ?
wsadata ends

sockaddr struct
    sa_family       word ?
    sa_data         byte 14 dup(?)
sockaddr ends

S_un_b struct
    s_b1            byte ?          ; Address octet 1
    s_b2            byte ?          ; Address octet 2
    s_b3            byte ?          ; Address octet 3
    s_b4            byte ?          ; Address octet 4
S_un_b ends

S_un_w struct
    s_w1            word ?          ; Address octets 1-2
    s_w2            word ?          ; Address octets 3-4
S_un_w ends

in_addr union
    UNION S_un
        s_un_b      <>              ; Address as four chars
        S_un_w      <>              ; Address as two ushorts
        S_addr      dword ?         ; Full address
    ENDS
in_addr ends

sockaddr_in struct
    sin_family      word ?
    sin_port        word ?
    sin_addr        in_addr <>
    sin_zero        byte 8 dup(?)
sockaddr_in ends

addrinfo struct
    ai_flags        dword ?
    ai_family       dword ?
    ai_socktype     dword ?
    ai_protocol     dword ?
    ai_addrlen      dword ?
    ai_canonname    byte ?
    ai_addr         qword ?
    ai_next         qword ?
addrinfo ends

timeval struct
    tv_sec          word ?           ; Seconds
    tv_usec         word ?           ; Microseconds
timeval ends


endif ; !_winsock_inc
