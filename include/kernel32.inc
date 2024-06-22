ifndef _kernel32_inc
_kernel32_inc equ <1>

;
; Constants
;

max_path                equ 260
startf_swind            equ 0x00000001
startf_usestdhandles    equ 0x00000100
startf_useshowwindow    equ 0x00000001
sw_hide                 equ 1
handle_flag_inherit     equ 0x00000001
infinite                equ 0xffffffff
std_input_handle        equ -10
error_handle_eof        equ 38

;
; Function prototypes
;

GetLastError            proto 
Sleep                   proto :dword
lstrlenW                proto :qword
CloseHandle             proto :qword
LocalFree               proto :qword
GetStdHandle            proto :dword
lstrcatA                proto :qword, :qword
GetCurrentDirectoryW    proto :qword, :qword
WinExec                 proto :qword, :dword
LocalAlloc              proto :dword, :qword
WaitForSingleObject     proto :qword, :dword        
GetEnvironmentVariableA proto :qword, :qword, :dword
SetHandleInformation    proto :qword, :dword, :dword
CreatePipe              proto :qword, :qword, :qword, :dword
ReadFile                proto :qword, :qword, :dword, :qword, :qword
ShellExecuteA           proto :dword, :qword, :qword, :qword, :qword, :dword
PeekNamedPipe           proto :qword, :qword, :dword, :qword, :qword, :qword
CreateProcessA          proto :qword, :qword, :qword, :qword, :dword, :dword, :qword, :qword, :qword, :qword
LoadLibraryA            proto :qword

;
; Data structures
;

STARTUPINFOA struct
    cbSize          DWORD   ?                ; 4 bytes
    align 8
    lpReserved      qword   ?                ; 8 bytes
    lpDesktop       qword   ?                ; 8 bytes
    lpTitle         qword   ?                ; 8 bytes
    align 4
    dwX             DWORD   ?                ; 4 bytes
    dwY             DWORD   ?                ; 4 bytes
    dwXSize         DWORD   ?                ; 4 bytes
    dwYSize         DWORD   ?                ; 4 bytes
    dwXCountChars   DWORD   ?                ; 4 bytes
    dwYCountChars   DWORD   ?                ; 4 bytes
    dwFillAttribute DWORD   ?                ; 4 bytes
    dwFlags         DWORD   ?                ; 4 bytes
    align 2
    wShowWindow     WORD    ?                ; 2 bytes
    cbReserved2     WORD    ?                ; 2 bytes
    align 8
    lpReserved2     qword   ?                ; 8 bytes
    hStdInput       qword   ?                ; 8 bytes
    hStdOutput      qword   ?                ; 8 bytes
    hStdError       qword   ?                ; 8 bytes
STARTUPINFOA ends

process_information struct
    hProcess        qword ?
    hThread         qword ?
    dwProcessId     dword ?
    dwThreadId      dword ?
process_information ends

security_attributes struct
    nLength                 dword ?
    lpSecurityDescriptor    qword ?
    padding1                dword ?
    bInheritHandle          qword ?
security_attributes ends

endif ; !_kernel32_inc
