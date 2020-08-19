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

#define EXIT_ROOT_RAX 0xdeadbeef
#define EXIT_ROOT_RCX 0xdeaffeed
#define EXIT_ROOT __asm__ __volatile__("cpuid"::"a"(EXIT_ROOT_RAX), "c"(EXIT_ROOT_RCX))

#endif
