#include "x64-utilities.h"
#include "mm.h"

#ifndef __HVC
#define __HVC

#define cprint(format, ...)	printk("[%02d] "format"\n", core, ##__VA_ARGS__)
#define gprint(format, ...)	printk("[  ] "format"\n", ##__VA_ARGS__)

typedef struct {
	cr4_t old_cr4;
	int vmxon_flag;

	unsigned long vmm_stack_base;
	#define VMM_STACK_ORDER 1
	int vmm_stack_order;
	unsigned long vmm_stack_top;
	
	unsigned long vmxon_region;
	unsigned long vmxon_paddr;
	
	unsigned long vmcs_region;
	unsigned long vmcs_paddr;

	unsigned long msr_bitmap;
	unsigned long msr_paddr;
	
	ept_data_t ept_data;
	int active_flag;
	int guest_flag;
} state_t;

typedef struct __attribute__((packed)) {
	unsigned long cr8;
	unsigned long rax;
	unsigned long rbx;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rbp;
	unsigned long rdi;
	unsigned long rsi;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long rflags;
} regs_t;

#define EXIT_NON_ROOT_RAX 0xdeadbeef
#define EXIT_NON_ROOT_RCX 0xdeaffeed
#define EXIT_NON_ROOT \
__asm__ __volatile__( \
	"pushf;" \
	"push %%r15;push %%r14;push %%r13;push %%r12;" \
	"push %%r11;push %%r10;push %%r9; push %%r8; " \
	"push %%rsi;push %%rdi;push %%rbp;push %%rdx;" \
	"push %%rbx;" \
	"cpuid;" \
	"pop %%rbx; pop %%rdx; pop %%rbp; pop %%rdi; " \
	"pop %%rsi; pop %%r8;  pop %%r9;  pop %%r10; " \
	"pop %%r11; pop %%r12; pop %%r13; pop %%r14; " \
	"pop %%r15;" \
	"popf;" \
	::"a"(EXIT_NON_ROOT_RAX), "c"(EXIT_NON_ROOT_RCX))

#define str2(x) #x
#define str(x) str2(x)

#endif
