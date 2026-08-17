.text
.globl elfTlsDescEntry
.hidden elfTlsDescEntry
.type elfTlsDescEntry,@function
elfTlsDescEntry:
    /*
     * A TLSDESC resolver does not use the normal SysV function ABI.  GCC and
     * clang treat the descriptor call as clobbering only %rax, so keep every
     * other caller-saved integer and SSE register intact while the C helper
     * lazily allocates the module's TLS block.
     *
     * There are eight pushes (64 bytes).  At function entry %rsp is 8 mod 16;
     * reserving another 264 bytes leaves it 16-byte aligned for the call.
     *
     * The CFI directives describe the frame so debuggers and profilers can
     * unwind through a descriptor call.
     */
    .cfi_startproc
    pushq %rdi
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rdi, 0
    pushq %rsi
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rsi, 0
    pushq %rdx
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rdx, 0
    pushq %rcx
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rcx, 0
    pushq %r8
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r8, 0
    pushq %r9
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r9, 0
    pushq %r10
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r10, 0
    pushq %r11
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r11, 0
    subq $264, %rsp
    .cfi_adjust_cfa_offset 264

    movdqu %xmm0, 0(%rsp)
    movdqu %xmm1, 16(%rsp)
    movdqu %xmm2, 32(%rsp)
    movdqu %xmm3, 48(%rsp)
    movdqu %xmm4, 64(%rsp)
    movdqu %xmm5, 80(%rsp)
    movdqu %xmm6, 96(%rsp)
    movdqu %xmm7, 112(%rsp)
    movdqu %xmm8, 128(%rsp)
    movdqu %xmm9, 144(%rsp)
    movdqu %xmm10, 160(%rsp)
    movdqu %xmm11, 176(%rsp)
    movdqu %xmm12, 192(%rsp)
    movdqu %xmm13, 208(%rsp)
    movdqu %xmm14, 224(%rsp)
    movdqu %xmm15, 240(%rsp)

    movq 8(%rax), %rdi
    call elfTlsDescAddress
    movq %fs:0, %rdx
    subq %rdx, %rax

    movdqu 0(%rsp), %xmm0
    movdqu 16(%rsp), %xmm1
    movdqu 32(%rsp), %xmm2
    movdqu 48(%rsp), %xmm3
    movdqu 64(%rsp), %xmm4
    movdqu 80(%rsp), %xmm5
    movdqu 96(%rsp), %xmm6
    movdqu 112(%rsp), %xmm7
    movdqu 128(%rsp), %xmm8
    movdqu 144(%rsp), %xmm9
    movdqu 160(%rsp), %xmm10
    movdqu 176(%rsp), %xmm11
    movdqu 192(%rsp), %xmm12
    movdqu 208(%rsp), %xmm13
    movdqu 224(%rsp), %xmm14
    movdqu 240(%rsp), %xmm15

    addq $264, %rsp
    .cfi_adjust_cfa_offset -264
    popq %r11
    .cfi_adjust_cfa_offset -8
    .cfi_restore %r11
    popq %r10
    .cfi_adjust_cfa_offset -8
    .cfi_restore %r10
    popq %r9
    .cfi_adjust_cfa_offset -8
    .cfi_restore %r9
    popq %r8
    .cfi_adjust_cfa_offset -8
    .cfi_restore %r8
    popq %rcx
    .cfi_adjust_cfa_offset -8
    .cfi_restore %rcx
    popq %rdx
    .cfi_adjust_cfa_offset -8
    .cfi_restore %rdx
    popq %rsi
    .cfi_adjust_cfa_offset -8
    .cfi_restore %rsi
    popq %rdi
    .cfi_adjust_cfa_offset -8
    .cfi_restore %rdi
    ret
    .cfi_endproc
.size elfTlsDescEntry, .-elfTlsDescEntry

.section .note.GNU-stack,"",@progbits
