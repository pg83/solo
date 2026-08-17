/*
 * getcontext/setcontext/swapcontext against the glibc ucontext_t layout, for
 * both architectures. The C side (makecontext) fills the same structure.
 *
 * x86-64 glibc offsets: gregs at 40 (R8 first), fpregs pointer at 224,
 * uc_sigmask at 296, __fpregs_mem at 424. aarch64: uc_link 8, uc_sigmask 40,
 * mcontext at 176 with regs[0] at 184, sp 432, pc 440; d8-d15 and fpcr/fpsr
 * go into __reserved at 464.
 */

#if defined(__x86_64__)

#define oRBP 120
#define oRSP 160
#define oRBX 128
#define oR8 40
#define oR9 48
#define oR12 72
#define oR13 80
#define oR14 88
#define oR15 96
#define oRDI 104
#define oRSI 112
#define oRDX 136
#define oRAX 144
#define oRCX 152
#define oRIP 168
#define oFPREGS 224
#define oSIGMASK 296
#define oFPREGSMEM 424

.text
.globl soloGetcontext
.hidden soloGetcontext
.type soloGetcontext,@function
soloGetcontext:
    .cfi_startproc
    movq %rbx, oRBX(%rdi)
    movq %rbp, oRBP(%rdi)
    movq %r12, oR12(%rdi)
    movq %r13, oR13(%rdi)
    movq %r14, oR14(%rdi)
    movq %r15, oR15(%rdi)
    movq %rdi, oRDI(%rdi)
    movq %rsi, oRSI(%rdi)
    movq %rdx, oRDX(%rdi)
    movq %rcx, oRCX(%rdi)
    movq %r8, oR8(%rdi)
    movq %r9, oR9(%rdi)
    movq (%rsp), %rcx
    movq %rcx, oRIP(%rdi)
    leaq 8(%rsp), %rcx
    movq %rcx, oRSP(%rdi)
    leaq oFPREGSMEM(%rdi), %rcx
    movq %rcx, oFPREGS(%rdi)
    fnstenv (%rcx)
    fldenv (%rcx)
    stmxcsr 24(%rcx)
    /* rt_sigprocmask(SIG_BLOCK, NULL, &uc_sigmask, 8) */
    leaq oSIGMASK(%rdi), %rdx
    xorl %esi, %esi
    xorl %edi, %edi
    movl $8, %r10d
    movl $14, %eax
    syscall
    xorl %eax, %eax
    ret
    .cfi_endproc
.size soloGetcontext, .-soloGetcontext

.globl soloSetcontext
.hidden soloSetcontext
.type soloSetcontext,@function
soloSetcontext:
    .cfi_startproc
    pushq %rdi
    /* rt_sigprocmask(SIG_SETMASK, &uc_sigmask, NULL, 8) */
    leaq oSIGMASK(%rdi), %rsi
    movl $2, %edi
    xorl %edx, %edx
    movl $8, %r10d
    movl $14, %eax
    syscall
    popq %rdi
    movq oFPREGS(%rdi), %rcx
    fldenv (%rcx)
    ldmxcsr 24(%rcx)
    movq oRBX(%rdi), %rbx
    movq oRBP(%rdi), %rbp
    movq oR12(%rdi), %r12
    movq oR13(%rdi), %r13
    movq oR14(%rdi), %r14
    movq oR15(%rdi), %r15
    movq oRSP(%rdi), %rsp
    movq oRIP(%rdi), %rcx
    pushq %rcx
    movq oRSI(%rdi), %rsi
    movq oRDX(%rdi), %rdx
    movq oRCX(%rdi), %rcx
    movq oR8(%rdi), %r8
    movq oR9(%rdi), %r9
    movq oRAX(%rdi), %rax
    movq oRDI(%rdi), %rdi
    ret
    .cfi_endproc
.size soloSetcontext, .-soloSetcontext

.globl soloSwapcontext
.hidden soloSwapcontext
.type soloSwapcontext,@function
soloSwapcontext:
    .cfi_startproc
    movq %rbx, oRBX(%rdi)
    movq %rbp, oRBP(%rdi)
    movq %r12, oR12(%rdi)
    movq %r13, oR13(%rdi)
    movq %r14, oR14(%rdi)
    movq %r15, oR15(%rdi)
    movq %rdi, oRDI(%rdi)
    movq %rsi, oRSI(%rdi)
    movq %rdx, oRDX(%rdi)
    movq %rcx, oRCX(%rdi)
    movq %r8, oR8(%rdi)
    movq %r9, oR9(%rdi)
    movq (%rsp), %rcx
    movq %rcx, oRIP(%rdi)
    leaq 8(%rsp), %rcx
    movq %rcx, oRSP(%rdi)
    leaq oFPREGSMEM(%rdi), %rcx
    movq %rcx, oFPREGS(%rdi)
    fnstenv (%rcx)
    stmxcsr 24(%rcx)
    /* The resumed side of the saved context returns 0. */
    movq $0, oRAX(%rdi)
    movq %rsi, %r12
    /* rt_sigprocmask(SIG_SETMASK, &new->uc_sigmask, &old->uc_sigmask, 8) */
    leaq oSIGMASK(%rdi), %rdx
    leaq oSIGMASK(%rsi), %rsi
    movl $2, %edi
    movl $8, %r10d
    movl $14, %eax
    syscall
    movq %r12, %rdi
    movq oFPREGS(%rdi), %rcx
    fldenv (%rcx)
    ldmxcsr 24(%rcx)
    movq oRBX(%rdi), %rbx
    movq oRBP(%rdi), %rbp
    movq oR12(%rdi), %r12
    movq oR13(%rdi), %r13
    movq oR14(%rdi), %r14
    movq oR15(%rdi), %r15
    movq oRSP(%rdi), %rsp
    movq oRIP(%rdi), %rcx
    pushq %rcx
    movq oRSI(%rdi), %rsi
    movq oRDX(%rdi), %rdx
    movq oRCX(%rdi), %rcx
    movq oR8(%rdi), %r8
    movq oR9(%rdi), %r9
    movq oRAX(%rdi), %rax
    movq oRDI(%rdi), %rdi
    ret
    .cfi_endproc
.size soloSwapcontext, .-soloSwapcontext

.globl soloStartContext
.hidden soloStartContext
.type soloStartContext,@function
soloStartContext:
    .cfi_startproc
    /* makecontext parked the successor context in %rbx. */
    movq %rbx, %rdi
    testq %rdi, %rdi
    je 1f
    call soloSetcontext
1:
    xorl %edi, %edi
    call exit
    .cfi_endproc
.size soloStartContext, .-soloStartContext

#elif defined(__aarch64__)

#define oLINK 8
#define oSIGMASK 40
#define oREGS 184
#define oSP 432
#define oPC 440
#define oFPSIMD 464

.text
.globl soloGetcontext
.hidden soloGetcontext
.type soloGetcontext,@function
soloGetcontext:
    .cfi_startproc
    str xzr, [x0, oREGS + 0 * 8]
    stp x18, x19, [x0, oREGS + 18 * 8]
    stp x20, x21, [x0, oREGS + 20 * 8]
    stp x22, x23, [x0, oREGS + 22 * 8]
    stp x24, x25, [x0, oREGS + 24 * 8]
    stp x26, x27, [x0, oREGS + 26 * 8]
    stp x28, x29, [x0, oREGS + 28 * 8]
    str x30, [x0, oREGS + 30 * 8]
    str x30, [x0, oPC]
    mov x2, sp
    str x2, [x0, oSP]
    add x2, x0, oFPSIMD
    stp d8, d9, [x2]
    stp d10, d11, [x2, 16]
    stp d12, d13, [x2, 32]
    stp d14, d15, [x2, 48]
    mrs x3, fpcr
    mrs x4, fpsr
    stp x3, x4, [x2, 64]
    /* rt_sigprocmask(SIG_BLOCK, NULL, &uc_sigmask, 8) */
    add x2, x0, oSIGMASK
    mov x0, 0
    mov x1, 0
    mov x3, 8
    mov x8, 135
    svc 0
    mov x0, 0
    ret
    .cfi_endproc
.size soloGetcontext, .-soloGetcontext

.globl soloSetcontext
.hidden soloSetcontext
.type soloSetcontext,@function
soloSetcontext:
    .cfi_startproc
    mov x9, x0
    /* rt_sigprocmask(SIG_SETMASK, &uc_sigmask, NULL, 8) */
    add x1, x9, oSIGMASK
    mov x0, 2
    mov x2, 0
    mov x3, 8
    mov x8, 135
    svc 0
    add x2, x9, oFPSIMD
    ldp d8, d9, [x2]
    ldp d10, d11, [x2, 16]
    ldp d12, d13, [x2, 32]
    ldp d14, d15, [x2, 48]
    ldp x3, x4, [x2, 64]
    msr fpcr, x3
    msr fpsr, x4
    ldp x18, x19, [x9, oREGS + 18 * 8]
    ldp x20, x21, [x9, oREGS + 20 * 8]
    ldp x22, x23, [x9, oREGS + 22 * 8]
    ldp x24, x25, [x9, oREGS + 24 * 8]
    ldp x26, x27, [x9, oREGS + 26 * 8]
    ldp x28, x29, [x9, oREGS + 28 * 8]
    ldr x30, [x9, oREGS + 30 * 8]
    ldr x2, [x9, oSP]
    mov sp, x2
    ldr x16, [x9, oPC]
    ldp x0, x1, [x9, oREGS + 0 * 8]
    ldp x2, x3, [x9, oREGS + 2 * 8]
    ldp x4, x5, [x9, oREGS + 4 * 8]
    ldp x6, x7, [x9, oREGS + 6 * 8]
    br x16
    .cfi_endproc
.size soloSetcontext, .-soloSetcontext

.globl soloSwapcontext
.hidden soloSwapcontext
.type soloSwapcontext,@function
soloSwapcontext:
    .cfi_startproc
    str xzr, [x0, oREGS + 0 * 8]
    stp x18, x19, [x0, oREGS + 18 * 8]
    stp x20, x21, [x0, oREGS + 20 * 8]
    stp x22, x23, [x0, oREGS + 22 * 8]
    stp x24, x25, [x0, oREGS + 24 * 8]
    stp x26, x27, [x0, oREGS + 26 * 8]
    stp x28, x29, [x0, oREGS + 28 * 8]
    str x30, [x0, oREGS + 30 * 8]
    str x30, [x0, oPC]
    mov x2, sp
    str x2, [x0, oSP]
    add x2, x0, oFPSIMD
    stp d8, d9, [x2]
    stp d10, d11, [x2, 16]
    stp d12, d13, [x2, 32]
    stp d14, d15, [x2, 48]
    mrs x3, fpcr
    mrs x4, fpsr
    stp x3, x4, [x2, 64]
    mov x9, x1
    /* rt_sigprocmask(SIG_SETMASK, &new->uc_sigmask, &old->uc_sigmask, 8) */
    add x2, x0, oSIGMASK
    add x1, x9, oSIGMASK
    mov x0, 2
    mov x3, 8
    mov x8, 135
    svc 0
    add x2, x9, oFPSIMD
    ldp d8, d9, [x2]
    ldp d10, d11, [x2, 16]
    ldp d12, d13, [x2, 32]
    ldp d14, d15, [x2, 48]
    ldp x3, x4, [x2, 64]
    msr fpcr, x3
    msr fpsr, x4
    ldp x18, x19, [x9, oREGS + 18 * 8]
    ldp x20, x21, [x9, oREGS + 20 * 8]
    ldp x22, x23, [x9, oREGS + 22 * 8]
    ldp x24, x25, [x9, oREGS + 24 * 8]
    ldp x26, x27, [x9, oREGS + 26 * 8]
    ldp x28, x29, [x9, oREGS + 28 * 8]
    ldr x30, [x9, oREGS + 30 * 8]
    ldr x2, [x9, oSP]
    mov sp, x2
    ldr x16, [x9, oPC]
    ldp x0, x1, [x9, oREGS + 0 * 8]
    ldp x2, x3, [x9, oREGS + 2 * 8]
    ldp x4, x5, [x9, oREGS + 4 * 8]
    ldp x6, x7, [x9, oREGS + 6 * 8]
    br x16
    .cfi_endproc
.size soloSwapcontext, .-soloSwapcontext

.globl soloStartContext
.hidden soloStartContext
.type soloStartContext,@function
soloStartContext:
    .cfi_startproc
    /* makecontext parked the successor context in x19. */
    mov x0, x19
    cbz x0, 1f
    bl soloSetcontext
1:
    mov w0, 0
    bl exit
    .cfi_endproc
.size soloStartContext, .-soloStartContext

#endif

.section .note.GNU-stack,"",@progbits
