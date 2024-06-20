ifndef _kernel32_inc
_kernel32_inc equ <1>

;
; Constants
;

max_path                equ 260
startf_swind            equ 0x00000001
startf_usestdhandles    equ 0x100
startf_useshowwindow    equ 0x00000001
sw_hide                 equ 1
handle_flag_inherit     equ 0x00000001


;
; Function prototypes
;

lstrlenW                proto :qword
GetLastError            proto :qword
CloseHandle             proto :qword
LocalFree               proto :qword
lstrcatA                proto :qword, :qword
GetCurrentDirectoryW    proto :qword, :qword
WinExec                 proto :qword, :dword
LocalAlloc              proto :dword, :qword              
GetEnvironmentVariableA proto :qword, :qword, :dword
SetHandleInformation    proto :qword, :dword, :dword
CreatePipe              proto :qword, :qword, :qword, :dword
ReadFile                proto :qword, :qword, :dword, :qword, :qword
ShellExecuteA           proto :dword, :qword, :qword, :qword, :qword, :dword
CreateProcessA          proto :qword, :qword, :qword, :qword, :dword, :dword, :qword, :qword, :qword, :qword
LoadLibraryA            proto :qword

;
; Data structures
;

startupinfoa struct 
    cbSize          dword ?
    lpReserved      qword ?
    lpDesktop       qword ?
    lpTitle         qword ?
    dwX             dword ?
    dwY             dword ?
    dwXSize         dword ?
    dwYSize         dword ?
    dwXCountChars   dword ?
    dwYCountChars   dword ?
    dwFillAttribute dword ?
    dwFlags         dword ?
    wShowWindow     word ?
    cbReserved2     word ?
    lpReserved2     qword ?
    hStdInput       qword ?
    hStdOutput      qword ?
    hStdError       qword ?
startupinfoa ends

process_information struct
    hProcess        qword ?
    hThread         qword ?
    dwProcessId     dword ?
    dwThreadId      dword ?
process_information ends

security_attributes struct
    nLength                 dword ?
    bInheritHandles         dword ?
    lpSecurityDescriptor    qword ?
security_attributes ends
endif ; !_kernel32_inc
