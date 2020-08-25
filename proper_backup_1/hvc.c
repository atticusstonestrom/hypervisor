//////////////////////////////////////////////////////
//                                                  //
//                                                  //
//                                                  //
//////////////////////////////////////////////////////



//////////////////////////////////////////////////////
//urgent todo:
//mutex, as in the intro to char devices
//	http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
//check physical address width?
//# of cores (and corresponding # of vmcs regions) as argument to open
//mutexes on all resources?
//all allocated pages should be writeback cacheable
//	save/restore caching type
//how does software check the amount of available ram
//	physical address width?
//	check virtualbox sliding ram
//	https://wiki.osdev.org/Detecting_Memory_(x86)
//save MSRs like ia32_lstar as part of guest_regs (at least writeable ones)
//lock cpuid?
//rflags should be found in guest state not regs_p!
//big problem if entry failure in vmresume
//sti could be problem in entry failure!
//should cr3 be kernel mode in vmx_exit?
//for exceptions:
//	need to account for bit 31 of idt-vectoring (double fault)
//	and for trap/fault rip modification
//	https://0xax.gitbooks.io/linux-insides/content/KernelStructures/linux-kernelstructure-1.html
//reg problems other than fs? seg fault...
//wrmsr bitmap
//	ia32_fs_base and ia32_gs_base
//	gs appears in hook; only alter on vmxoff
//cr2 after vmresume fails(/exit)
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "x64-utilities.h"
#include "vtx-utilities.h"
#include "vmcs.h"
#include "mm.h"
#include "hvc.h"

static int param_cpu_id;
module_param(param_cpu_id, int, (S_IRUSR|S_IRGRP|S_IROTH));
MODULE_PARM_DESC(param_cpu_id, "cpu id that operations run on");

#define DEVICE_NAME "hvchar"
#define CLASS_NAME "hvc"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Atticus Stonestrom");
MODULE_DESCRIPTION("...");
MODULE_VERSION("0.01");

/////////////////////////////////////////
//character device variables
static int major_num;
static struct class *hvc_class=NULL;
static struct device *hvc_device=NULL;

static int global_open(struct inode *, struct file *);
static int global_close(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
	.open=global_open,
	.read=dev_read,
	.write=dev_write,
	.release=global_close };
/////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
int ncores;

unsigned long *ret_rsp;
//unsigned long *ret_rbp;

typedef struct __attribute__((packed)) {
	unsigned char read_low[1024];	//0x00000000 to 0x00001fff
	unsigned char read_high[1024];	//0xc0000000 to 0xc0001fff
	unsigned char write_low[1024];	//0x00000000 to 0x00001fff
	unsigned char write_high[1024]; //0xc0000000 to 0xc0001fff
} msr_bitmap_t;
unsigned long msr_bitmap;

#define set_rdmsr_bmp(val)									\
if((signed)val<=0x1fff) {									\
	((msr_bitmap_t *)msr_bitmap)->read_low[(val)>>3]|=1<<((val)&0x07); }			\
else if((signed)val>=0xc0000000 && (signed)val<=0xc0001fff) {					\
	((msr_bitmap_t *)msr_bitmap)->read_high[((val)-0xc0000000)>>3]|=1<<((val)&0x07); }

#define set_wrmsr_bmp(val)									\
if((signed)val<=0x1fff) {									\
	((msr_bitmap_t *)msr_bitmap)->write_low[(val)>>3]|=1<<((val)&0x07); }			\
else if((signed)val>=0xc0000000 && (signed)val<=0xc0001fff) {					\
	((msr_bitmap_t *)msr_bitmap)->write_high[((val)-0xc0000000)>>3]|=1<<((val)&0x07); }
//((msr_bitmap_t *)msr_bitmap)->read_low[0x277>>3]|=1<<(0x277&0x07);

int *errors=NULL;	//every entry should be non-positive
#define parse_errors(i) ({ for(i=0;i<ncores;i++) { if(errors[i]) break; } (i==ncores) ? 0:errors[i]; })

state_t *state=NULL;
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
enum cr_access_type {
	MOV_TO=0,
	MOV_FROM=1,
	CLTS=2,
	LMSW=3 };
enum mov_cr_registers {
	MOV_CR_RAX=0,
	MOV_CR_RCX=1,
	MOV_CR_RDX=2,
	MOV_CR_RBX=3,
	MOV_CR_RSP=4,
	MOV_CR_RBP=5,
	MOV_CR_RSI=6,
	MOV_CR_RDI=7,
	MOV_CR_R8=8,
	MOV_CR_R9=9,
	MOV_CR_R10=10,
	MOV_CR_R11=11,
	MOV_CR_R12=12,
	MOV_CR_R13=13,
	MOV_CR_R14=14,
	MOV_CR_R15=15 };
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long cr_num:4;
		unsigned long access_type:2;
		unsigned long lmsw_operand_type:1;	//0=register, 1=memory
		unsigned long rsv_7:1;
		unsigned long mov_cr_reg:4;
		unsigned long rsv_12_15:4;
		unsigned long lmsw_src_data:16;
		unsigned long rsv_32_63:32; }
		cr_access;
	
	struct __attribute__((packed)) {
		unsigned long addr; }
		page_fault;
	
	unsigned long val;
} exit_qualification_t;
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
//static void hook(struct guest_regs *regs_p);
//push regs, mov %rsp, first arg (rax?)
//specify calling convention? gcc
//returns flag for vmxoff
#define EXIT_HANDLER_RESUME		0
#define EXIT_HANDLER_ENTRY_FAILURE	1
#define EXIT_HANDLER_EXIT		2
__attribute__((__used__))
static unsigned long hook(regs_t *regs_p) {
	int core=get_cpu();
	//int core=smp_processor_id();
	//cprint("in hook!");
	//put_cpu();
	//return EXIT_HANDLER_ENTRY_FAILURE;
	
	lhf_t lhf;
	unsigned long rip, length;
	
	exit_reason_t reason={ .val=0xdeadbeef };
	exit_qualification_t qual;
	unsigned long cpl;
	
	VMREAD(cpl, GUEST_CS_SELECTOR, lhf);
	cpl &= 0x03;
	
	VMREAD(reason.val, EXIT_REASON, lhf);
	VMREAD(qual.val, EXIT_QUALIFICATION, lhf);
	//cprint("exit reason: 0x%x\texit qual: 0x%lx\tcpl: %ld", reason.val, qual.val, cpl);
	
	//unsigned long guest_ss, host_ss;
	//VMREAD(guest_ss, GUEST_FS_BASE, lhf);
	//VMREAD(host_ss, HOST_FS_BASE, lhf);
	//if(host_ss!=guest_ss) {
	//	msr=(msr_t){ .val=guest_ss };
	//	WRITE_MSR(msr, IA32_FS_BASE);
	//	//cprint("fs change: 0x%lx => 0x%lx", host_ss, guest_ss);
	//	VMWRITE(guest_ss, HOST_FS_BASE, lhf); }
	//VMREAD(guest_ss, GUEST_GS_BASE, lhf);
	//VMREAD(host_ss, HOST_GS_BASE, lhf);
	//if(host_ss!=guest_ss) {
	//	msr=(msr_t){ .val=guest_ss };
	//	WRITE_MSR(msr, IA32_GS_BASE);
	//	//cprint("gs change: 0x%lx => 0x%lx", host_ss, guest_ss);
	//	VMWRITE(guest_ss, HOST_GS_BASE, lhf); }
	
	cpuid_t cpuid;
	msr_t msr;
	unsigned long reg, reg2;
	interruption_info_t interruption_info;
	
	//if(reason.basic_exit_reason==ER_HLT) {
	//	cprint("hlt");
	//	put_cpu();
	//	return EXIT_HANDLER_EXIT; }
	
	if(reason.vm_entry_failure) {
		cprint("entry failure");
		switch (reason.basic_exit_reason) {
		case ER_INVL_GUEST_STATE:
		case ER_MSR_LOADING:
		case ER_MACHINE_CHECK:
		default:
			break; };
		put_cpu();
		return EXIT_HANDLER_ENTRY_FAILURE; }
		
	
	switch (reason.basic_exit_reason) {
			
	case ER_EXCEPTION_OR_NMI:
		VMREAD(interruption_info.val, EXIT_INTERRUPTION_INFO, lhf);
		VMREAD(reg, EXIT_INTERRUPTION_ERROR_CODE, lhf);
			
		VMREAD(rip, GUEST_RIP, lhf);
		cprint("intrrpt info: 0x%x\terror code: 0x%lx\trip: 0x%lx",
		       interruption_info.val, reg, rip);
			
		interruption_info.iret_nmi_unblocking=0;
		VMWRITE(interruption_info.val, ENTRY_INTERRUPTION_INFO, lhf);
		VMWRITE(reg, ENTRY_EXCEPTION_ERROR_CODE, lhf);

		//if(interruption_info.vector==0x0d) {
		//	cprint("gp fault: 0x%lx 0x%lx (len %ld)",
		//	       *(unsigned long *)rip, *(unsigned long *)(rip+8),
		//	       length); }
		if(1<<interruption_info.vector==((exception_bitmap_t){.pf=1}).val) {
			regs_p->cr2=qual.page_fault.addr; }
		VMREAD(length, EXIT_INSTRUCTION_LENGTH, lhf);
		if(interruption_info.type==IRQ_TYPE_SW_I || interruption_info.type==IRQ_TYPE_SW_E || interruption_info.type==IRQ_TYPE_P_SW_E) {
			VMWRITE(length, ENTRY_INSTRUCTION_LENGTH, lhf); }
		rip-=length;
		VMWRITE(rip, GUEST_RIP, lhf);
		break;

	case ER_CPUID:
		//lock prefix? #UD
		cprint("cpuid exit:\tleaf: 0x%lx\targ: 0x%lx", regs_p->rax, regs_p->rcx);

		if(regs_p->rax==EXIT_NON_ROOT_RAX && regs_p->rcx==EXIT_NON_ROOT_RCX && !cpl) {
			cprint("vmx exit requested");
			VMREAD(rip, GUEST_RIP, lhf);
			VMREAD(length, EXIT_INSTRUCTION_LENGTH, lhf);
			rip+=length;
			VMWRITE(rip, GUEST_RIP, lhf);
			put_cpu();
			return EXIT_HANDLER_EXIT; }

		CPUID(cpuid, regs_p->rax, regs_p->rcx);
		if(regs_p->rax==0) {
			//cpuid.leaf_0.vendor_id={'K', 'e', 'r', 'n', 'e', 'l', 'F', 'u', 'z', 'z', 'e', 'r'};
			memcpy(cpuid.leaf_0.vendor_id, "KernelFuzzer", 12);
			reg=cpuid.leaf_0.ecx;
			cpuid.edx=cpuid.leaf_0.edx;
			cpuid.ecx=reg; }
		if(regs_p->rax==1) {
			cpuid.leaf_1.vmx=0;
			cpuid.leaf_1.hypervisor_present=1; }
		//https://lwn.net/Articles/301888/

		regs_p->rax=cpuid.eax;
		regs_p->rbx=cpuid.ebx;
		regs_p->rcx=cpuid.ecx;
		regs_p->rdx=cpuid.edx;
		break;

	case ER_RDMSR:
		//lock prefix? #UD
		cprint("rdmsr exit:\tid: 0x%lx", regs_p->rcx);

		if(((regs_p->rcx)>0x00001fff && (regs_p->rcx)<0xc0000000)
		   || (regs_p->rcx)>0xc0001fff || cpl>0) {
			cprint("cpl non-zero or msr invalid");
			//reflect back #GP(0)
			regs_p->rax=0;
			regs_p->rdx=0;
			break; }

		READ_MSR(msr, regs_p->rcx);	//first check TRUE ctls
		if(regs_p->rcx==IA32_VMX_BASIC) {
			msr=(msr_t) {.val=0xdeadbeef}; }
			
		regs_p->rax=msr.eax;
		regs_p->rdx=msr.edx;
		break;

	case ER_WRMSR:
		cprint("wrmsr exit:\tid: 0x%lx", regs_p->rcx);

		if(((regs_p->rcx)>0x00001fff && (regs_p->rcx)<0xc0000000)
		   || (regs_p->rcx)>0xc0001fff || cpl>0) {
			cprint("cpl non-zero or msr invalid");
			//reflect back #GP(0)
			regs_p->rax=0;
			regs_p->rdx=0;
			break; }
			
		msr.eax=regs_p->rax;
		msr.edx=regs_p->rdx;
		WRITE_MSR(msr, regs_p->rcx);	//first check TRUE ctls
		break;
	
	case ER_CR_ACCESS:
		if(cpl>0) {
			cprint("cpl non-zero");
			//reflect back #GP(0)
			break; }
		
		#define MOV_CR8 0xdeadbeef
		switch (qual.cr_access.cr_num) {
			case(0): reg=GUEST_CR0; break;
			case(3): reg=GUEST_CR3; break;
			case(4): reg=GUEST_CR4; break;
			case(8): reg=MOV_CR8; break; };
			
		switch(qual.cr_access.access_type) {
		case(MOV_TO):
			switch(qual.cr_access.mov_cr_reg) {
				case(MOV_CR_RAX): reg2=regs_p->rax; break;
				case(MOV_CR_RCX): reg2=regs_p->rcx; break;
				case(MOV_CR_RDX): reg2=regs_p->rdx; break;
				case(MOV_CR_RBX): reg2=regs_p->rbx; break;
				case(MOV_CR_RSP): VMREAD(reg2, GUEST_RSP, lhf); break;
				case(MOV_CR_RBP): reg2=regs_p->rbp; break;
				case(MOV_CR_RSI): reg2=regs_p->rsi; break;
				case(MOV_CR_RDI): reg2=regs_p->rdi; break;
				case(MOV_CR_R8):  reg2=regs_p->r8;  break;
				case(MOV_CR_R9):  reg2=regs_p->r9;  break;
				case(MOV_CR_R10): reg2=regs_p->r10; break;
				case(MOV_CR_R11): reg2=regs_p->r11; break;
				case(MOV_CR_R12): reg2=regs_p->r12; break;
				case(MOV_CR_R13): reg2=regs_p->r13; break;
				case(MOV_CR_R14): reg2=regs_p->r14; break;
				case(MOV_CR_R15): reg2=regs_p->r15; break;
				default: break; };
			if(reg==GUEST_CR3) { reg2&=0x000fffffffffffff; }
			if(reg==MOV_CR8) { regs_p->cr8=reg2; }
			else { VMWRITE(reg2, reg, lhf); }
			if(reg==GUEST_CR3) { VMWRITE((0xffffffffffffe7ff&reg2), HOST_CR3, lhf); }
				
			break;
		case(MOV_FROM):
			if(reg==MOV_CR8) { reg2=regs_p->cr8; }
			else { VMREAD(reg2, reg, lhf); }
			switch(qual.cr_access.mov_cr_reg) {
				case(MOV_CR_RAX): regs_p->rax=reg2; break;
				case(MOV_CR_RCX): regs_p->rcx=reg2; break;
				case(MOV_CR_RDX): regs_p->rdx=reg2; break;
				case(MOV_CR_RBX): regs_p->rbx=reg2; break;
				case(MOV_CR_RSP): VMWRITE(reg2, GUEST_RSP, lhf); break;
				case(MOV_CR_RBP): regs_p->rbp=reg2; break;
				case(MOV_CR_RSI): regs_p->rsi=reg2; break;
				case(MOV_CR_RDI): regs_p->rdi=reg2; break;
				case(MOV_CR_R8):  regs_p->r8=reg2;  break;
				case(MOV_CR_R9):  regs_p->r9=reg2;  break;
				case(MOV_CR_R10): regs_p->r10=reg2; break;
				case(MOV_CR_R11): regs_p->r11=reg2; break;
				case(MOV_CR_R12): regs_p->r12=reg2; break;
				case(MOV_CR_R13): regs_p->r13=reg2; break;
				case(MOV_CR_R14): regs_p->r14=reg2; break;
				case(MOV_CR_R15): regs_p->r15=reg2; break; 
				default: break; };
			break;
		case(CLTS):
			VMREAD(reg, GUEST_CR0, lhf);
			reg &= ~(((cr0_t){ .ts=1 }).val);
			VMWRITE(reg, GUEST_CR0, lhf);
			break;
		case(LMSW):
			//page fault???
			VMREAD(reg, GUEST_CR0, lhf);
			reg &= 0xffffffffffff0000;
			reg |= qual.cr_access.lmsw_src_data;
			VMWRITE(reg, GUEST_CR0, lhf);
			break;
		default: break; };
		//check for error with lhf
		//cr4 vmxe, shadow/mask. how to handle?
		break;
			
	case ER_VMCALL:
	case ER_VMCLEAR:
	case ER_VMLAUNCH:
	case ER_VMPTRLD:
	case ER_VMPTRST:
	case ER_VMREAD:
	case ER_VMRESUME:
	case ER_VMWRITE:
	case ER_VMXOFF:
	case ER_VMXON:
		if(cpl>0) {
			cprint("cpl non-zero");
			//reflect back #GP(0)
			break; }
		regs_p->rflags |= ((rflags_t){ .cf=1 }).val;
		regs_p->rflags &= ~(((rflags_t){ .pf=1, .af=1, .zf=1, .sf=1, .of=1 }).val);
		break;
	
	case ER_INVEPT:
	case ER_INVVPID:
		//#UD
		if(cpl>0) {
			cprint("cpl non-zero");
			//reflect back #GP(0)
			break; }
		//vpid, etc
		break;

	case ER_XSETBV:
		if(cpl>0 || regs_p->rcx!=0 || (regs_p->rax&1)==0 || (regs_p->rax&0x06)>>1==2) {
			//reflect back #GP(0)
			break; }
		__asm__ __volatile__("xsetbv"::"a"(regs_p->rax), "c"(regs_p->rcx), "d"(regs_p->rdx));
		break;

	case ER_GETSEC:
	case ER_INVD:
	default:
		cprint("cannot handle");
		break; };
	
	VMREAD(rip, GUEST_RIP, lhf);
	VMREAD(length, EXIT_INSTRUCTION_LENGTH, lhf);
	rip+=length;
	VMWRITE(rip, GUEST_RIP, lhf);

	put_cpu();
	return EXIT_HANDLER_RESUME; }

void vmresume_failure_handler(lhf_t lhf) {
	int core=get_cpu();
	unsigned long error_code;
	if(VMfailValid(lhf)) {
		VMREAD(error_code, VM_INSTRUCTION_ERROR, lhf);
		cprint("\033[103;5;34;1m vmlaunch failed with error code %ld \033[0m", error_code); }
	else if(VMfailInvalid(lhf)) {
		cprint("vmlaunch failed with invalid region"); }
	cprint("\033[103;5;94;1m core unstable, reboot recommended!! \033[0m");
	put_cpu();
	return; }

#define HOST_CR3  0x00006c02
#define GUEST_CR3 0x00006802
#define GUEST_RSP 0x0000681c
#define GUEST_RIP 0x0000681e
#define EXIT_INSTRUCTION_LENGTH 0x0000440c
#define GUEST_FS_BASE 0x0000680e
#define HOST_FS_BASE  0x00006c06
#define GUEST_GS_BASE 0x00006810
#define HOST_GS_BASE  0x00006c08
__asm__(
	".text;"
	".global host_stub;"
"host_stub:;"
	//"cli;"
	PUSHA
	"mov %cr8, %rax;"
	"push %rax;"
	"mov %cr2, %rax;"
	"push %rax;"
	"mov %rsp, %rdi;"
	"call hook;"

	"cmp $"str(EXIT_HANDLER_EXIT)", %eax;"
	"je vmx_exit;"
	"cmp $"str(EXIT_HANDLER_RESUME)", %eax;"
	"je vmx_resume;"
	"cmp $"str(EXIT_HANDLER_ENTRY_FAILURE)", %eax;"
	"je vmx_entry_failure;"

"vmx_resume:;"
	"pop %rax;"
	"mov %rax, %cr2;"
	"pop %rax;"
	"mov %rax, %cr8;"
	POPA
	//"sti;"
	"vmresume;"
	
	"push %rbp;"
	"push %rax;"
	"push %rbx;"
	"push %rcx;"
	"push %rdx;"
	"push %rdi;"
	
	"lahf;"
	"shr $8, %rax;"
	"movzbl %al, %edi;"
	PUSHA
	"call vmresume_failure_handler;"
	POPA
	
	"mov %rsp, %rbp;"
	"mov $"str(GUEST_RSP)", %ebx;"
	"vmread %rbx, %rsp;"
	
	"mov $"str(GUEST_FS_BASE)", %ebx;"
	"vmread %rbx, %rdx;"
	"mov %edx, %eax;"
	"shr $32, %rdx;"
	"mov $"str(IA32_FS_BASE)", %ecx;"
	"wrmsr;"
	
	"mov $"str(GUEST_GS_BASE)", %ebx;"
	"vmread %rbx, %rdx;"
	"mov %edx, %eax;"
	"shr $32, %rdx;"
	"mov $"str(IA32_GS_BASE)", %ecx;"
	"wrmsr;"
	
	"mov $"str(GUEST_RIP)", %ebx;"
	"vmread %rbx, %rbx;"
	
	"push %rbx;"
	"movq (%rbp), %rdi;"
	"movq 8(%rbp), %rdx;"
	"movq 16(%rbp), %rcx;"
	"movq 24(%rbp), %rbx;"
	"movq 32(%rbp), %rax;"
	"movq 40(%rbp), %rbp;"
	"ret;"

"vmx_entry_failure:;"
	"pop %rax;"
	"mov %rax, %cr2;"
	"pop %rax;"
	"mov %rax, %cr8;"
	POPA
	//"sti;"
	"jmp return_from_entry_failure;"

"vmx_exit:;"	//cr3?
	"pop %rax;"
	"mov %rax, %cr2;"
	"pop %rax;"
	"mov %rax, %cr8;"
	POPA
	"push %rbp;"
	"push %rax;"
	"push %rbx;"
	"push %rcx;"
	"push %rdx;"
	"mov %rsp, %rbp;"

	"mov $"str(GUEST_RSP)", %ebx;"
	"vmread %rbx, %rsp;"
	
	"mov $"str(GUEST_FS_BASE)", %ebx;"
	"vmread %rbx, %rdx;"
	"mov %edx, %eax;"
	"shr $32, %rdx;"
	"mov $"str(IA32_FS_BASE)", %ecx;"
	"wrmsr;"
	
	"mov $"str(GUEST_GS_BASE)", %ebx;"
	"vmread %rbx, %rdx;"
	"mov %edx, %eax;"
	"shr $32, %rdx;"
	"mov $"str(IA32_GS_BASE)", %ecx;"
	"wrmsr;"
	
	"mov $"str(GUEST_RIP)", %ebx;"
	"vmread %rbx, %rbx;"
	
	"push %rbx;"
	"movq (%rbp), %rdx;"
	"movq 8(%rbp), %rcx;"
	"movq 16(%rbp), %rbx;"
	"movq 24(%rbp), %rax;"
	"movq 32(%rbp), %rbp;"
	//"sti;"
	"ret;" );
extern void host_stub(void);
//try vmlaunch here
//if fails then "call vmfail"

__asm__(
	".text;"
	".global guest_stub;"
"guest_stub:;"
	"mov $"str(IA32_VMX_BASIC)", %ecx;"
	"rdmsr;"
	"rdtsc;"
	"mov $0xdeadbeef, %eax;"
	"mov $0xfeeddeaf, %r8;"
	"push %rax;"
	"hlt;");
extern void guest_stub(void);
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void core_exit(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	free_ept(&(state[core].ept_data));	//printk??
	if(state[core].vmxon_region) {
		free_page(state[core].vmxon_region);
		cprint("freed vmxon region:\t0x%lx", state[core].vmxon_region);
		state[core].vmxon_region=0; }
	if(state[core].vmcs_region) {
		free_page(state[core].vmcs_region);
		cprint("freed vmcs region:\t\t0x%lx", state[core].vmcs_region);
		state[core].vmcs_region=0; }
	if(state[core].vmm_stack_base) {
		free_pages(state[core].vmm_stack_base, state[core].vmm_stack_order);
		cprint("freed vmm stack:\t\t0x%lx (%d pages)",
		       state[core].vmm_stack_base, 1<<state[core].vmm_stack_order);
		state[core].vmm_stack_base=0; }
	if(state[core].msr_bitmap) {
		free_page(state[core].msr_bitmap);
		cprint("freed msr bitmap:\t\t0x%lx", state[core].msr_bitmap);
		state[core].msr_bitmap=0; }
	
	return; }

static void global_exit(void) {
	if(state==NULL) {
		return; }
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	gprint("cleaning up cores");
	on_each_cpu(core_exit, NULL, 1);
	gprint("all clean\n");
	
	if(msr_bitmap) {
		free_page(msr_bitmap);
		gprint("freed 'msr_bitmap':\t0x%lx", msr_bitmap);
		msr_bitmap=0; }
	
	//if(ret_rbp!=NULL) {
	//	kfree(ret_rbp);
	//	gprint("freed 'ret_rbp':\t\t0x%px", ret_rbp);
	//	ret_rbp=NULL; }
	
	if(ret_rsp!=NULL) {
		kfree(ret_rsp);
		gprint("freed 'ret_rbp':\t\t0x%px", ret_rsp);
		ret_rsp=NULL; }
	
	if(errors!=NULL) {
		kfree(errors);
		gprint("freed 'errors':\t\t0x%px", errors);
		errors=NULL; }
	
	if(state!=NULL) {
		kfree(state);
		gprint("freed 'state':\t\t0x%px", state);
		state=NULL; }
	
	printk("\n–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	
	device_destroy(hvc_class, MKDEV(major_num, 0));
	class_unregister(hvc_class);
	class_destroy(hvc_class);
	unregister_chrdev(major_num, DEVICE_NAME);
	
	return; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void core_close(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	if(state[core].guest_flag) {
		EXIT_NON_ROOT;
		state[core].guest_flag=0; }
	
	int success_flag;
	
	lhf_t lhf;
	if(state[core].active_flag && state[core].vmcs_paddr) {
		VMCLEAR(state[core].vmcs_paddr, lhf);
		success_flag=VMsucceed(lhf) ? 1:0;
		state[core].active_flag=1-success_flag;
		cprint("cleared vmcs:\t\t0x%lx\t%s", state[core].vmcs_paddr, success_flag ? "[done]":"[failed]"); }
		
	if(state[core].vmxon_flag) {
		VMXOFF;
		cprint("exited vmx mode");
		state[core].vmxon_flag=0; }
	
	cr4_t cr4;
	if(state[core].old_cr4.val) {
		__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
		__asm__ __volatile__("mov %0, %%cr4"::"r"(state[core].old_cr4.val));
		cprint("restored cr4:\t\t0x%lx => 0x%lx", cr4.val, state[core].old_cr4.val);
		state[core].old_cr4.val=0; }
	
	return; }

static int global_close(struct inode *inodep, struct file *filep) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	gprint("exiting vmx operation");
	on_each_cpu(core_close, NULL, 1);
	gprint("exited\n");
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	return 0; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
void core_launch(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	lhf_t lhf={0};
	unsigned long error_code;
	__asm__ __volatile__(
		"mov %%cr3, %%rcx;"
		"mov $"str(GUEST_CR3)", %%ebx;"
		"vmwrite %%rcx, %%rbx;"
		"mov $"str(HOST_CR3)", %%ebx;"
		"vmwrite %%rcx, %%rbx;"
		
		"mov $"str(IA32_FS_BASE)", %%ecx;"
		"rdmsr;"
		"shl $32, %%rdx;"
		"or %%rax, %%rdx;"
		"mov $"str(GUEST_FS_BASE)", %%ebx;"
		"vmwrite %%rdx, %%rbx;"
		"mov $"str(HOST_FS_BASE)", %%ebx;"
		"vmwrite %%rdx, %%rbx;"

		"mov $"str(IA32_GS_BASE)", %%ecx;"
		"rdmsr;"
		"shl $32, %%rdx;"
		"or %%rax, %%rdx;"
		"mov $"str(GUEST_GS_BASE)", %%ebx;"
		"vmwrite %%rdx, %%rbx;"
		"mov $"str(HOST_GS_BASE)", %%ebx;"
		"vmwrite %%rdx, %%rbx;"
		
		"mov $"str(GUEST_RSP)", %%ebx;"
		"vmwrite %%rsp, %%rbx;"
		
		"lea vmx_entry_point(%%rip), %%rcx;"
		"mov $"str(GUEST_RIP)", %%ebx;"
		"vmwrite %%rcx, %%rbx;"
		
		"mov $0x0b, %%eax;"
		"cpuid;"
		"movq (ret_rsp), %%rax;"
		"mov %%rsp, (%%rax, %%rdx, 8);"
		//"movq (ret_rbp), %%rax;"
		//"mov %%rbp, (%%rax, %%rdx, 8);"
		
		"lahf;"
		"and $0xbe, %%ah;"
		"vmlaunch;"
		"lahf;"
		
	"vmx_entry_point:;"
		"shr $8, %%rax;"
		"movb %%al, %0;"
		:"=r"(lhf.val)
		::"rax", "rbx", "rcx", "rdx", "memory");

	//cpuid_t cpuid;
	//CPUID(cpuid.leaf_0, 0);
	//cprint("%.12s", cpuid.leaf_0.vendor_id);
	//EXIT_NON_ROOT;
	//errors[core]=-EINVAL;
	//if(state[core].active_flag) {
	//	return; }
	
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			VMREAD(error_code, VM_INSTRUCTION_ERROR, lhf);
			cprint("vmlaunch failed with error code %ld", error_code); }
		else if(VMfailInvalid(lhf)) {
			cprint("vmlaunch failed with invalid region"); }
		errors[core]=-EINVAL;
		return; }
	state[core].guest_flag=1;
	if(state[core].active_flag) {
		return; }
	
	//__asm__ __volatile__(		//cannot rely on guest state to be reliable
	//"return_from_entry_failure:;"
	//	"mov $"str(GUEST_RSP)", %rbx;"
	//	"vmread %rbx, %rsp;");
	__asm__ __volatile__(
	"return_from_entry_failure:;"
		"mov $0x0b, %%eax;"
		"cpuid;"
		"movq (ret_rsp), %%rax;"
		"movq (%%rax, %%rdx, 8), %%rsp;"
		//"movq (ret_rbp), %%rax;"
		//"movq (%%rax, %%rdx, 8), %%rbp;"
		:::"rax", "rbx", "rcx", "rdx", "memory");
	errors[core]=-EINVAL;
	return; }

static void core_open(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	(void)memset((void *)state[core].vmxon_region, 0, 4096);
	(void)memset((void *)state[core].vmcs_region, 0, 4096);
	cprint("zeroed:\tvmxon region: 0x%lx\t\tvmcs region: 0x%lx",
	       state[core].vmxon_region, state[core].vmcs_region);
	
	cr4_t cr4;
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	state[core].old_cr4.val=cr4.val;
	cr4.vmxe=1;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	cprint("set cr4.vmxe[bit 13]:\t0x%lx => 0x%lx", state[core].old_cr4.val, cr4.val);
	
	msr_t msr;
	READ_MSR(msr, IA32_VMX_BASIC);
	cprint("revision id:\t\t0x%x", msr.vmx_basic.revision_id);
	*(unsigned int *)(state[core].vmxon_region)=msr.vmx_basic.revision_id;
	lhf_t lhf;
	VMXON(state[core].vmxon_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmxon failed");
		errors[core]=-EINVAL;
		return; }
	cprint("vmxon succeeded");
	state[core].vmxon_flag=1;
	

	READ_MSR(msr, IA32_VMX_BASIC);
	*(unsigned int *)(state[core].vmcs_region)=msr.vmx_basic.revision_id;
	*(unsigned int *)(state[core].vmcs_region)&=0x7fffffff;	//not a shadow vmcs
	VMCLEAR(state[core].vmcs_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmclear failed");
		errors[core]=-EINVAL;
		return; }
	cprint("cleared vmcs:\t\t0x%lx", state[core].vmcs_paddr);
	VMPTRLD(state[core].vmcs_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmptrld failed");
		errors[core]=-EINVAL;
		return; }
	state[core].active_flag=1;
	cprint("vmcs region activated:\t0x%lx", state[core].vmcs_paddr);
	
	return; }

static int global_open(struct inode *inodep, struct file *filep) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	int ret=0, i=0;
	
	(void)memset((void *)msr_bitmap, 0, 4096);
	gprint("zeroed msr bitmap:\t0x%lx\n", msr_bitmap);
	set_rdmsr_bmp(IA32_VMX_BASIC);
	//((msr_bitmap_t *)msr_bitmap)->read_low[0x277>>3]|=1<<(0x277&0x07);
	//TODO must handle appropriately here
	
	gprint("entering vmx operation");
	on_each_cpu(core_open, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to enter, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("vmx operation entered\n");
	
	gprint("initializing vmcss");
	on_each_cpu(core_fill_vmcs, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to initialize vmcs, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("initialized\n");

	gprint("entering guest state");
	on_each_cpu(core_launch, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vm entry failed, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("vm entry succeeded\n");
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");

	return 0; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void __init core_check_vmx_support(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	cpuid_t cpuid;
	CPUID(cpuid.leaf_0, 0);
	if(strncmp(cpuid.leaf_0.vendor_id, "GenuineIntel", 12)) {
		cprint("vendor id: '%.12s'\t\t[not intel]", cpuid.leaf_0.vendor_id);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("vendor id: '%.12s'\t\t[okay]", cpuid.leaf_0.vendor_id);
	
	CPUID(cpuid, 1);
	if(!(cpuid.leaf_1.vmx)) {
		cprint("cpuid.1:ecx.vmx[bit 5]: %d\t\t[not supported]", cpuid.leaf_1.vmx);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("cpuid.1:ecx.vmx[bit 5]: %d\t\t[okay]", cpuid.leaf_1.vmx);
	
	msr_t new_msr, msr;
	READ_MSR(msr, IA32_FEATURE_CONTROL);
	if(msr.feature_control.lock) {
		//should check if current processor state is smx
		if(!msr.feature_control.non_smx_vmxe) {
			cprint("ia32_feature_control: 0x%lx\t\t[non-smx vt-x disabled]", msr.val);
			errors[core]=-EOPNOTSUPP;
			return; }
		cprint("ia32_feature_control: 0x%lx\t\t[okay]", msr.val); }
	else {
		new_msr.val=msr.val;
		new_msr.feature_control.non_smx_vmxe=1;
		new_msr.feature_control.lock=1;
		WRITE_MSR(new_msr, IA32_FEATURE_CONTROL);
		cprint("ia32_feature_control: 0x%lx => 0x%lx\t\t[locked]", msr.val, new_msr.val); }
	
	READ_MSR(msr, IA32_PAT);
	if(msr.pat.entries[0]!=PAT_WB && msr.pat.entries[4]!=PAT_WB) {
		cprint("pat entries: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [wb caching unavailable]",
		       msr.pat.entries[0], msr.pat.entries[1], msr.pat.entries[2], msr.pat.entries[3], 
		       msr.pat.entries[4], msr.pat.entries[5], msr.pat.entries[6], msr.pat.entries[7]);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("pat entries: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [wb caching available]",
	       msr.pat.entries[0], msr.pat.entries[1], msr.pat.entries[2], msr.pat.entries[3], 
	       msr.pat.entries[4], msr.pat.entries[5], msr.pat.entries[6], msr.pat.entries[7]);
	
	return; }

static void __init core_init(void *info) {
	int core=smp_processor_id();
	state[core]=(state_t) {0};
	errors[core]=0;
	
	int ret=0;
	
	state[core].msr_bitmap=msr_bitmap;
	state[core].msr_paddr=virt_to_phys((void *)msr_bitmap);

	if(( ret=alloc_wb_page(&(state[core].vmxon_region), &(state[core].vmxon_paddr)) )) {
		cprint("failed to allocate wb-cacheable vmxon region");
		errors[core]=ret;
		return; }
	cprint("vmxon region:\t\t0x%lx", state[core].vmxon_region);

	if(( ret=alloc_wb_page(&(state[core].vmcs_region), &(state[core].vmcs_paddr)) )) {
		cprint("failed to allocate wb-cacheable vmcs region");
		errors[core]=ret;
		return; }
	cprint("vmcs region:\t\t0x%lx", state[core].vmcs_region);
	
	if(( ret=initialize_ept(&state[core].ept_data, MAX_ORD_GUEST_PAGES) )) {
		cprint("failed to initialize ept");
		errors[core]=ret;
		return; }
	
	state[core].vmm_stack_order=VMM_STACK_ORDER;
	if( !(state[core].vmm_stack_base=__get_free_pages(__GFP_ZERO, state[core].vmm_stack_order)) ) {
		cprint("failed to allocate vmm stack");
		errors[core]=-ENOMEM;
		return; }
	cprint("vmm stack:\t\t\t0x%lx (%d pages)", state[core].vmm_stack_base, 1<<(state[core].vmm_stack_order));
	state[core].vmm_stack_top=state[core].vmm_stack_base+((1<<12)<<(state[core].vmm_stack_order));

	return; }

static int __init global_init(void) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	int i, ret=0;

	ncores=num_online_cpus();
	gprint("number of online cores: %d", ncores);
	
	state=NULL;
	state=kmalloc(ncores*sizeof(state_t), __GFP_ZERO);
	if(state==NULL) {
		gprint("failed to allocate 'state' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'state':\t0x%px", ncores*sizeof(state_t), state);

	errors=NULL;
	errors=kmalloc(ncores*sizeof(int), __GFP_ZERO);
	if(errors==NULL) {
		gprint("failed to allocate 'errors' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'errors':\t0x%px", ncores*sizeof(int), errors);
	
	ret_rsp=NULL;
	ret_rsp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	if(ret_rsp==NULL) {
		gprint("failed to allocate 'ret_rsp' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'ret_rsp':\t0x%px", ncores*sizeof(long), ret_rsp);

	//ret_rbp=NULL;
	//ret_rbp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	//if(ret_rbp==NULL) {
	//	gprint("failed to allocate 'ret_rbp' memory\n");
	//	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	//	global_exit();
	//	return -ENOMEM; }
	//gprint("got %ld bytes for 'ret_rbp':\t0x%px", ncores*sizeof(long), ret_rbp);
	
	msr_bitmap=0;
	msr_bitmap=get_zeroed_page(GFP_KERNEL);
	if(!msr_bitmap) {
		gprint("failed to allocate 'msr_bitmap' page\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got page for msr bitmap:\t\t0x%lx\n", msr_bitmap);

	gprint("confirming vmx support");
	on_each_cpu(core_check_vmx_support, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vmx unsupported, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return ret; }
	gprint("vmx support confirmed\n");
	
	
	gprint("allocating vmm memory");
	on_each_cpu(core_init, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to enter, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return ret; }
	gprint("all allocated\n");
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	
	
	//printk("[*] initializing the hvchar lkm\n");
	if( (major_num=register_chrdev(0, DEVICE_NAME, &fops))<0 ) {
		printk("[*] failed to register a major number\n");
		return major_num; }
	//printk("[*] registered correctly with major number %d\n", major_num);
	
	hvc_class=class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(hvc_class)) {
		unregister_chrdev(major_num, DEVICE_NAME);
		printk("[*] failed to register device class\n");
		return PTR_ERR(hvc_class); }
	//printk("[*] device class registered correctly\n");
	
	hvc_device=device_create(hvc_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
	if(IS_ERR(hvc_device)) {
		class_destroy(hvc_class);
		unregister_chrdev(major_num, DEVICE_NAME);
		printk("[*] failed to create the device\n");
		return PTR_ERR(hvc_device); }
	//printk("[*] device class created correctly\n");

	return 0; }
//////////////////////////////////////////////////////////////////////////////////

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
	return 0; }
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
	return 0; }


module_init(global_init);
module_exit(global_exit);
