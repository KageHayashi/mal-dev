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

NtQueryInformationProcess PROC
    mov currentHash, 079229C4Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtReadVirtualMemory PROC
    mov currentHash, 0831C899Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 08B0E8995h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtResumeThread PROC
    mov currentHash, 0270825A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtCreateProcess PROC
    mov currentHash, 0E698E514h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

end