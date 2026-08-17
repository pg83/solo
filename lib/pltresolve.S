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

.section .note.GNU-stack,"",@progbits
