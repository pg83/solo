/* The loader's assembly halves: the TLSDESC resolver and the lazy PLT
 * binder, whose C sides live in elf_loader.cpp. */

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
