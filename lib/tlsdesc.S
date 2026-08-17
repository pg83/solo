#if defined(__x86_64__)

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

#elif defined(__aarch64__)

.text
.globl elfTlsDescEntry
.hidden elfTlsDescEntry
.type elfTlsDescEntry,@function
elfTlsDescEntry:
    /*
     * The aarch64 TLSDESC contract: x0 holds the address of the descriptor
     * pair, the resolver returns the variable's offset from the thread
     * pointer in x0, and every other register survives.  The C helper can
     * clobber anything caller-saved, so the whole caller-saved register file
     * is spilled: x1-x18, the frame pair, and all 32 vector registers, since
     * the upper halves of v8-v15 are caller-saved too.
     */
    .cfi_startproc
    sub sp, sp, #704
    .cfi_def_cfa_offset 704
    stp x29, x30, [sp]
    .cfi_rel_offset x29, 0
    .cfi_rel_offset x30, 8
    mov x29, sp
    stp x1, x2, [sp, #16]
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    stp x7, x8, [sp, #64]
    stp x9, x10, [sp, #80]
    stp x11, x12, [sp, #96]
    stp x13, x14, [sp, #112]
    stp x15, x16, [sp, #128]
    stp x17, x18, [sp, #144]
    stp q0, q1, [sp, #176]
    stp q2, q3, [sp, #208]
    stp q4, q5, [sp, #240]
    stp q6, q7, [sp, #272]
    stp q8, q9, [sp, #304]
    stp q10, q11, [sp, #336]
    stp q12, q13, [sp, #368]
    stp q14, q15, [sp, #400]
    stp q16, q17, [sp, #432]
    stp q18, q19, [sp, #464]
    stp q20, q21, [sp, #496]
    stp q22, q23, [sp, #528]
    stp q24, q25, [sp, #560]
    stp q26, q27, [sp, #592]
    stp q28, q29, [sp, #624]
    stp q30, q31, [sp, #656]

    ldr x0, [x0, #8]
    bl elfTlsDescAddress
    mrs x1, tpidr_el0
    sub x0, x0, x1

    ldp q0, q1, [sp, #176]
    ldp q2, q3, [sp, #208]
    ldp q4, q5, [sp, #240]
    ldp q6, q7, [sp, #272]
    ldp q8, q9, [sp, #304]
    ldp q10, q11, [sp, #336]
    ldp q12, q13, [sp, #368]
    ldp q14, q15, [sp, #400]
    ldp q16, q17, [sp, #432]
    ldp q18, q19, [sp, #464]
    ldp q20, q21, [sp, #496]
    ldp q22, q23, [sp, #528]
    ldp q24, q25, [sp, #560]
    ldp q26, q27, [sp, #592]
    ldp q28, q29, [sp, #624]
    ldp q30, q31, [sp, #656]
    ldp x1, x2, [sp, #16]
    ldp x3, x4, [sp, #32]
    ldp x5, x6, [sp, #48]
    ldp x7, x8, [sp, #64]
    ldp x9, x10, [sp, #80]
    ldp x11, x12, [sp, #96]
    ldp x13, x14, [sp, #112]
    ldp x15, x16, [sp, #128]
    ldp x17, x18, [sp, #144]
    ldp x29, x30, [sp]
    .cfi_restore x29
    .cfi_restore x30
    add sp, sp, #704
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
.size elfTlsDescEntry, .-elfTlsDescEntry

#endif

.section .note.GNU-stack,"",@progbits
