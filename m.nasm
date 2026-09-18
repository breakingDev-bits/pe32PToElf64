global _start

section .text
_start:
    xor rax, rax
    mov rax, 3

    mov r10, rcx
    mov eax, 0x002C
    syscall
    ret

