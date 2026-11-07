#include "textflag.h"

TEXT libc_ioctl_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_ioctl(SB)

GLOBL	·libcIoctlTrampolineAddr(SB), RODATA, $8
DATA	·libcIoctlTrampolineAddr(SB)/8, $libc_ioctl_trampoline<>(SB)
