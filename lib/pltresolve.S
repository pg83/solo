#if defined(__x86_64__)

.text
.globl elfPltResolveEntry
.hidden elfPltResolveEntry
.type elfPltResolveEntry,@function
elfPltResolveEntry:
    /*
     * The lazy binder. A PLT entry pushed the relocation index and PLT0
     * pushed the link map, so on entry [%rsp] is the link map, 8(%rsp) the
     * index, and %rsp is 8 mod 16. Preserve every register that can carry
     * arguments while the C resolver patches the GOT slot; fxsave covers x87
     * and the XMM halves, so 256/512-bit vector arguments lose their upper
     * lanes, like pre-AVX glibc.
     *
     * Eight pushes (64 bytes) plus 520 keep the fxsave area 16-aligned.
     */
    .cfi_startproc
    .cfi_def_cfa_offset 24
    pushq %rax
    .cfi_adjust_cfa_offset 8
    pushq %rcx
    .cfi_adjust_cfa_offset 8
    pushq %rdx
    .cfi_adjust_cfa_offset 8
    pushq %rsi
    .cfi_adjust_cfa_offset 8
    pushq %rdi
    .cfi_adjust_cfa_offset 8
    pushq %r8
    .cfi_adjust_cfa_offset 8
    pushq %r9
    .cfi_adjust_cfa_offset 8
    pushq %r10
    .cfi_adjust_cfa_offset 8
    subq $520, %rsp
    .cfi_adjust_cfa_offset 520
    fxsave64 (%rsp)

    movq 584(%rsp), %rdi
    movq 592(%rsp), %rsi
    call elfPltResolve
    movq %rax, %r11

    fxrstor64 (%rsp)
    addq $520, %rsp
    .cfi_adjust_cfa_offset -520
    popq %r10
    .cfi_adjust_cfa_offset -8
    popq %r9
    .cfi_adjust_cfa_offset -8
    popq %r8
    .cfi_adjust_cfa_offset -8
    popq %rdi
    .cfi_adjust_cfa_offset -8
    popq %rsi
    .cfi_adjust_cfa_offset -8
    popq %rdx
    .cfi_adjust_cfa_offset -8
    popq %rcx
    .cfi_adjust_cfa_offset -8
    popq %rax
    .cfi_adjust_cfa_offset -8
    addq $16, %rsp
    .cfi_adjust_cfa_offset -16
    jmp *%r11
    .cfi_endproc
.size elfPltResolveEntry, .-elfPltResolveEntry

#elif defined(__aarch64__)

.text
.globl elfPltResolveEntry
.hidden elfPltResolveEntry
.type elfPltResolveEntry,@function
elfPltResolveEntry:
    /*
     * The lazy binder. PLT0 pushed the pair {x16 = &GOT[n], x30}, then set
     * x16 = &GOT[2] and jumped here through GOT[2]. GOT[1] holds the link
     * map, and the .rela.plt index is the GOT slot's distance from GOT[3].
     * Only the registers that carry arguments need to survive: x0-x8 and
     * q0-q7; everything else a normal call would clobber anyway.
     */
    .cfi_startproc
    .cfi_def_cfa_offset 16
    .cfi_rel_offset x30, 8
    stp x29, x30, [sp, #-224]!
    .cfi_adjust_cfa_offset 224
    .cfi_rel_offset x29, 0
    mov x29, sp
    stp x0, x1, [sp, #16]
    stp x2, x3, [sp, #32]
    stp x4, x5, [sp, #48]
    stp x6, x7, [sp, #64]
    str x8, [sp, #80]
    stp q0, q1, [sp, #96]
    stp q2, q3, [sp, #128]
    stp q4, q5, [sp, #160]
    stp q6, q7, [sp, #192]

    ldur x0, [x16, #-8]
    ldr x1, [sp, #224]
    sub x1, x1, x16
    lsr x1, x1, #3
    sub x1, x1, #1
    bl elfPltResolve
    mov x17, x0

    ldp q0, q1, [sp, #96]
    ldp q2, q3, [sp, #128]
    ldp q4, q5, [sp, #160]
    ldp q6, q7, [sp, #192]
    ldp x0, x1, [sp, #16]
    ldp x2, x3, [sp, #32]
    ldp x4, x5, [sp, #48]
    ldp x6, x7, [sp, #64]
    ldr x8, [sp, #80]
    ldp x29, x30, [sp], #224
    .cfi_adjust_cfa_offset -224
    .cfi_restore x29
    ldp x16, x30, [sp], #16
    .cfi_adjust_cfa_offset -16
    .cfi_restore x30
    br x17
    .cfi_endproc
.size elfPltResolveEntry, .-elfPltResolveEntry

#endif

.section .note.GNU-stack,"",@progbits
