ifndef _ntdll_inc
_ntdll_inc equ <1>

;
; Function prototypes
;

RtlZeroMemory   proto :qword, :qword
RtlCopyMemory   proto :qword, :qword, :qword

endif ; !_ntdll_inc
