/* The zero terminator of .eh_frame. A hosted link takes it from the
   toolchain's crtend.o; this -nostdlib link has no crtend.o, and GNU ld
   does not synthesize one, so an unwinder searching for a pc that has no
   FDE (musl's start code, reached by a guest's backtrace()) would scan
   past the end of the section into garbage. lld rebuilds .eh_frame and
   drops this empty record, emitting its own terminator. Must stay the
   last .eh_frame contribution in the link. */
	.section .eh_frame,"a",%progbits
	.p2align 2
	.long 0
