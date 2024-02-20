.data
currentHash DWORD 0

.code
EXTERN SW2_GetSyscallNumber: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret
WhisperMain ENDP

NtCreateProcess PROC
    mov currentHash, 00FA70E2Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateThreadEx PROC
    mov currentHash, 096B7D009h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtOpenProcess PROC
    mov currentHash, 0D457CDDBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtOpenProcessToken PROC
    mov currentHash, 001116D8Ch    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtTestAlert PROC
    mov currentHash, 0FF55E13Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtOpenThread PROC
    mov currentHash, 0F4A8E810h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtSuspendProcess PROC
    mov currentHash, 0C23FDBD3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 0FEDEFC78h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtResumeProcess PROC
    mov currentHash, 0F3ADC821h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtResumeThread PROC
    mov currentHash, 08C9C41CEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtGetContextThread PROC
    mov currentHash, 068CC221Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtSetContextThread PROC
    mov currentHash, 015BF4B04h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtClose PROC
    mov currentHash, 0009B91B7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtReadVirtualMemory PROC
    mov currentHash, 0852D93C3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 003AD192Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 00590373Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 005890EFBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 00D963529h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtQuerySystemInformation PROC
    mov currentHash, 008131970h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 0F224EA92h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQueryInformationFile PROC
    mov currentHash, 0F8F89679h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtQueryInformationProcess PROC
    mov currentHash, 08A178B9Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtQueryInformationThread PROC
    mov currentHash, 0EF20C3E0h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtCreateSection PROC
    mov currentHash, 072A5143Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtOpenSection PROC
    mov currentHash, 00AA22C2Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtMapViewOfSection PROC
    mov currentHash, 0336017ABh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 0FD4E1818h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 08B9E1395h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 00C9BCAB8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtQueueApcThread PROC
    mov currentHash, 00B2C47FCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 01190390Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

end