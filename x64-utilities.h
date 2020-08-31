#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>

#ifndef X64_UTILITIES
#define X64_UTILITIES

/////////////////////////////////////////////////////
// to-do: paging entry structure 
// push %fs? push %gs?
// struct gdte_t?
// syscall prologue
// irq stack
// constrain eax and edx in READ_MSR?
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
#define DISABLE_RW_PROTECTION			\
__asm__ __volatile__(				\
	"mov %%cr0, %%rax;"			\
	"and $0xfffffffffffeffff, %%rax;"	\
	"mov %%rax, %%cr0;"			\
	:::"rax")			

#define ENABLE_RW_PROTECTION \
__asm__ __volatile__(				\
	"mov %%cr0, %%rax;"			\
	"or $0x10000, %%rax;"			\
	"mov %%rax, %%cr0;"			\
	:::"rax")
/////////////////////////////////////////////////////


/////////////////////////////////////////////////////
#define SC_NUM "335"
/////////////////////////////////////////////////////


/////////////////////////////////////////////////////
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned int eax;
		unsigned int edx; };
	unsigned long val;
	
	#define IA32_FEATURE_CONTROL 0x3a
	struct __attribute__((packed)) {
		unsigned long lock:1;
		unsigned long smx_vmxe:1;
		unsigned long non_smx_vmxe:1;
		unsigned long rsv_3_7:5;
		unsigned long local_senter_enable:7;
		unsigned long global_senter_enable:1;
		unsigned long rsv_16:1;
		unsigned long sgx_launch_enable:1;
		unsigned long sgx_global_enable:1;
		unsigned long rsv_19:1;
		unsigned long lmce:1;
		unsigned long rsv_21_63:43; }
		feature_control;
	
	#define IA32_MTRRCAP 0xfe
	struct __attribute__((packed)) {
		unsigned long vcnt:8;
		unsigned long fix:1;
		unsigned long rsv_9:1;
		unsigned long wc:1;
		unsigned long smrr:1;
		unsigned long rsv_12_63:52; }
		mtrrcap;
	
	#define IA32_MTRR_DEF_TYPE 0x2ff
	struct __attribute__((packed)) {
		unsigned long type:8;
		unsigned long rsv_8_9:2;
		unsigned long fe:1;
		unsigned long e:1;
		unsigned long rsv_12_63:52; }
		mtrr_def_type;
	
	#define IA32_MTRR_FIX64K_00000 0x250
	#define IA32_MTRR_FIX16K_80000 0x258
	#define IA32_MTRR_FIX16K_A0000 0x259
	#define IA32_MTRR_FIX4K_C0000  0x268
	#define IA32_MTRR_FIX4K_C8000  0x269
	#define IA32_MTRR_FIX4K_D0000  0x26a
	#define IA32_MTRR_FIX4K_D8000  0x26b
	#define IA32_MTRR_FIX4K_E0000  0x26c
	#define IA32_MTRR_FIX4K_E8000  0x26d
	#define IA32_MTRR_FIX4K_F0000  0x26e
	#define IA32_MTRR_FIX4K_F8000  0x26f
	struct __attribute__((packed)) {
		unsigned char entries[8]; }
		mtrr_fixed;
	
	#define IA32_MTRR_PHYSBASE(n) (0x200+2*(n))
	#define IA32_MTRR_PHYSMASK(n) (0x201+2*(n))
	struct __attribute__((packed)) {
		unsigned long type:8;
		unsigned long rsv_8_10:3;
		unsigned long v:1;		//"addr" field also used for mask
		unsigned long addr:52; }	//must be shifted left 12 bits
		mtrr_variable;
	
	#define IA32_PAT 0x277
	struct __attribute__((packed)) {
		unsigned char entries[8]; }
		pat;
	
	#define IA32_VMX_BASIC 0x480
	struct __attribute__((packed)) {
		unsigned long revision_id:31;
		unsigned long rsv_31:1;
		unsigned long vm_region_size:13;
		unsigned long rsv_45_47:3;
		unsigned long address_width:1;		//if set, 32 bits. else physical address width
		unsigned long dual_monitor:1;
		unsigned long vm_caching_type:4;	//will be PAT_WB at present
		unsigned long vm_exit_info_io:1;
		unsigned long vmx_controls_clear:1;	//<- bit 55
		unsigned long vm_entry_exception:1;
		unsigned long rsv_57_63:7; }
		vmx_basic;
	
	#define IA32_VMX_PINBASED_CTLS 0x481
	#define IA32_VMX_PROCBASED_CTLS 0x482
	#define IA32_VMX_EXIT_CTLS 0x483
	#define IA32_VMX_ENTRY_CTLS 0x484
	#define IA32_VMX_PROCBASED_CTLS2 0x48b
	#define IA32_VMX_TRUE_PINBASED_CTLS 0x48d
	#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48e
	#define IA32_VMX_TRUE_EXIT_CTLS 0x48f
	#define IA32_VMX_TRUE_ENTRY_CTLS 0x490
	struct __attribute__((packed)) {
		unsigned int allowed_zeroes;
		unsigned int allowed_ones; }	//always correct, w or w/o TRUE
		vmx_ctls;
	
	#define IA32_VMX_MISC 0x485
	struct __attribute__((packed)) {
		unsigned long vpt_tsc_relationship:5;	//vmx preemption timer
		unsigned long ia32_efer_lma_str:1;
		unsigned long hlt_support:1;		//activity state 1
		unsigned long shutdown_support:1;	//activity state 2
		unsigned long wait_for_sipi_support:1;	//activity state 3
		unsigned long rsv_9_13:5;	//set to 0
		unsigned long pt_allowed:1;
		unsigned long ia32_smbase_msr_in_smm:1;
		unsigned long max_cr3_target_count:9;
		unsigned long max_msr_ld_list:5;	//512*(N+1)
		unsigned long vmxoff_smi_blocks_allowed:1;
		unsigned long vmwrite_to_vm_exit_info_allowed:1;
		unsigned long instruction_length_0_injection_allowed:1;
		unsigned long rsv_31;		//set to 0
		unsigned long mseg_revision_id:32; }
		vmx_misc;
	
	#define IA32_VMX_CR0_FIXED0 0x486
	#define IA32_VMX_CR0_FIXED1 0x487
	#define IA32_VMX_CR4_FIXED0 0x488
	#define IA32_VMX_CR4_FIXED1 0x489
	struct __attribute__((packed)) {
		unsigned long cr; }
		vmx_cr_fixed_bits;
	
	#define IA32_VMX_VMCS_ENUM 0x48a
	struct __attribute__((packed)) {
		unsigned long rsv_0:1;		//set to 0
		unsigned long highest_vmcs_encoding_index_val:9;
		unsigned long rsv_10_63:54; }	//set to 0
		vmx_vmcs_enum;
	
	#define IA32_VMX_EPT_VPID_CAP	 0x48c
	struct __attribute__((packed)) {
		//rsv bits set to 0
		unsigned long x_only_ept_translations:1;
		unsigned long rsv_1_5:5;
		unsigned long page_walk_len_4_support:1;
		unsigned long rsv_7:1;
		unsigned long caching_type_uc_allowed:1;
		unsigned long rsv_9_13:5;
		unsigned long caching_type_wb_allowed:1;
		unsigned long rsv_15:1;
		unsigned long two_mb_pages_allowed:1;
		unsigned long one_gb_pages_allowed:1;
		unsigned long rsv_18_19:2;
		unsigned long invept_supported:1;
		unsigned long accessed_dirty_flags_allowed:1;
		unsigned long ept_violation_exit_info:1;
		unsigned long shadow_stack_control_supported:1;
		unsigned long rsv_24:1;
		unsigned long single_context_invept_supported:1;
		unsigned long all_context_invept_supported:1;
		unsigned long rsv_27_31:5;
		unsigned long invvpid_supported:1;
		unsigned long rsv_33_39:7;
		unsigned long individual_addr_invvpid_supported:1;
		unsigned long single_context_invvpid_supported:1;
		unsigned long all_context_invvpid_supported:1;
		unsigned long retaining_globals_invvpid_supported:1;
		unsigned long rsv_44_63:20; }
		vmx_ept_vpid_cap;

	#define IA32_VMX_VMFUNC 0x491
	unsigned long vmx_vmfunc;
	
	#define IA32_FS_BASE 0xc0000100
	#define IA32_GS_BASE 0xc0000101
	
	
	#define IA32_DEBUGCTL 0x1d9
	#define IA32_SYSENTER_CS 0x174
	#define IA32_SYSENTER_ESP 0x175
	#define IA32_SYSENTER_EIP 0x176
	#define IA32_PERF_GLOBAL_CTRL 0x38f
	#define IA32_EFER 0xc0000080
	#define IA32_BNDCFGS 0xd90
	#define IA32_RTIT_CTL 0x570
	#define IA32_S_CET 0x6a2
	#define IA32_INTERRUPT_SSP_TABLE_ADDR 0x6a8
	#define IA32_PKRS 0x6e1
} msr_t;

#define READ_MSR(dst, id)  __asm__ __volatile__("rdmsr":"=a"((dst).eax), "=d"((dst).edx):"c"(id):"memory")
#define WRITE_MSR(src, id) __asm__ __volatile__("wrmsr"::"a"((src).eax), "d"((src).edx), "c"(id):"memory")
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long pe:1;
		unsigned long mp:1;
		unsigned long em:1;
		unsigned long ts:1;
		unsigned long et:1;
		unsigned long ne:1;
		unsigned long rsv_6_15:10;
		unsigned long wp:1;
		unsigned long rsv_17:1;
		unsigned long am:1;
		unsigned long rsv_19_28:10;
		unsigned long nw:1;
		unsigned long cd:1;
		unsigned long pg:1;
		unsigned long rsv_32_63:32; };
	unsigned long val;
} cr0_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long vme:1;
		unsigned long pvi:1;
		unsigned long tsd:1;
		unsigned long de:1;
		unsigned long pse:1;
		unsigned long pae:1;
		unsigned long mce:1;
		unsigned long pge:1;
		unsigned long pce:1;
		unsigned long osfxsr:1;
		unsigned long osxmmexcpt:1;
		unsigned long umip:1;
		unsigned long la57:1;
		unsigned long vmxe:1;
		unsigned long smxe:1;
		unsigned long rsv_15:1;
		unsigned long fsgsbase:1;
		unsigned long pcide:1;
		unsigned long osxsave:1;
		unsigned long rsv_19:1;
		unsigned long smep:1;
		unsigned long smap:1;
		unsigned long pke:1;
		unsigned long rsv_23_63:31; };
	unsigned long val;
} cr4_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long cf:1;
		unsigned long rsv_1:1;
		unsigned long pf:1;
		unsigned long rsv_3:1;
		unsigned long af:1;
		unsigned long rsv_5:1;
		unsigned long zf:1;
		unsigned long sf:1;
		unsigned long tf:1;
		unsigned long _if:1;
		unsigned long df:1;
		unsigned long of:1;
		unsigned long iopl:2;
		unsigned long nt:1;
		unsigned long rsv_15:1;
		unsigned long rf:1;
		unsigned long vm:1;
		unsigned long ac:1;
		unsigned long vif:1;
		unsigned long vip:1;
		unsigned long id:1;
		unsigned long rsv_22_31:10;
		unsigned long rsv_32_63:32; };
	unsigned long val;
} rflags_t;
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
//should check ID flag (bit 21) of EFLAGS
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned int eax;
		unsigned int ebx;
		unsigned int ecx;
		unsigned int edx; };
	
	union __attribute__((packed)) {
		struct __attribute__((packed)) {
			unsigned int eax;
			unsigned int ebx;
			unsigned int edx;
			unsigned int ecx; };
		struct __attribute__((packed)) {
			unsigned int max_basic_leaf;
			char vendor_id[12]; }; }
		leaf_0;
	
	struct __attribute__((packed)) {
		unsigned int version_info;		//eax start/end
		unsigned int brand_index:8;		//ebx start
		unsigned int clflush_line_size:8;
		unsigned int max_num_ids:8;
		unsigned int apic_id:8;			//ebx end
		unsigned int ecx_0_4:5;			//ecx start
		unsigned int vmx:1;
		unsigned int ecx_6_30:25;
		unsigned int hypervisor_present:1;	//ecx end
		unsigned int edx_0_11:12;		//edx start
		unsigned int mtrr:1;
		unsigned int edx_13_15:3;
		unsigned int pat:1;
		unsigned int edx_17_31:15; }		//edx end
		leaf_1;
	
	struct __attribute__((packed)) {
		unsigned int maxphyaddr:8;
		unsigned int eax_8_31:24;
		unsigned int ebx;
		unsigned int ecx;
		unsigned int edx; }
		leaf_80000008;
} cpuid_t;
	
#define CPUID2(dst, leaf) 							\
__asm__ __volatile__(								\
	"cpuid;"								\
	:"=a"((dst).eax), "=b"((dst).ebx), "=c"((dst).ecx), "=d"((dst).edx)	\
	:"a"(leaf):"memory")

#define CPUID3(dst, leaf, arg) 							\
__asm__ __volatile__(								\
	"cpuid;"								\
	:"=a"((dst).eax), "=b"((dst).ebx), "=c"((dst).ecx), "=d"((dst).edx)	\
	:"a"(leaf), "c"(arg)							\
	:"memory")

#define GET_CPUID_ARGS(_1,_2,_3,NAME,...) NAME
#define CPUID(...) GET_CPUID_ARGS(__VA_ARGS__, CPUID3, CPUID2)(__VA_ARGS__)
/////////////////////////////////////////////////////


/////////////////////////////////////////////////////
typedef struct __attribute__((packed)) {
	unsigned short offset_0_15;
	unsigned short segment_selector;
	unsigned char ist;			//interrupt stack table
	unsigned char type:4;
	unsigned char zero_12:1;
	unsigned char dpl:2;			//descriptor privilege level
	unsigned char p:1;			//present flag
	unsigned short offset_16_31;
	unsigned int offset_32_63;
	unsigned int rsv;
} idte_t;

typedef struct __attribute__((packed)) {
	unsigned short lim_val;
	struct idte_t *addr;
} idtr_t;

#define READ_IDT(dst)	\
__asm__ __volatile__(	\
	"cli;"		\
	"sidt %0;"	\
	"sti;"		\
	:: "m"(dst)	\
	: "memory")

#define WRITE_IDT(src)	\
__asm__ __volatile__(	\
	"cli;"		\
	"lidt %0;"	\
	"sti;"		\
	:: "m"(src)	\
	: "memory")
/////////////////////////////////////////////////////


/////////////////////////////////////////////////////
#define PUSHA \
	"pushf;""push %r15;""push %r14;""push %r13;"\
	"push %r12;""push %r11;""push %r10;""push %r9;"\
	"push %r8;""push %rsi;""push %rdi;""push %rbp;"\
	"push %rdx;""push %rcx;""push %rbx;""push %rax;"

#define POPA \
	"pop %rax;""pop %rbx;""pop %rcx;""pop %rdx;"\
	"pop %rbp;""pop %rdi;""pop %rsi;""pop %r8;"\
	"pop %r9;""pop %r10;""pop %r11;""pop %r12;"\
	"pop %r13;""pop %r14;""pop %r15;""popf;"
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
#define INVLPG(addr) __asm__ __volatile__("invlpg (%0)"::"r"(addr):"memory")
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
typedef struct __attribute__((packed)) {
	unsigned short lim_val;
	unsigned long base;
} dtr_t;
/////////////////////////////////////////////////////

/////////////////////////////////////////////////////
typedef struct __attribute__((packed)) {
	unsigned short lim_val;
	void *addr;
} gdtr_t;

typedef struct __attribute__((packed)) {
	unsigned short seg_lim_0_15;
	unsigned short base_addr_0_15;
	unsigned char base_addr_16_23;		//interrupt stack table
	unsigned char type:4;
	unsigned char zero_12:1;
	unsigned char dpl:2;			//descriptor privilege level
	unsigned char p:1;			//present flag
	unsigned char seg_lim_16_19:4;
	unsigned char avl:1;			//available for use
	unsigned char zero_20_21:2;
	unsigned char granularity:1;
	unsigned char base_addr_24_31;
	unsigned int base_addr_32_63;
	unsigned int rsv;
} tssd_t;

typedef struct __attribute__((packed)) {
	unsigned int rsv_0_3;
	unsigned long rsp0;
	unsigned long rsp1;
	unsigned long rsp2;
	unsigned long rsv_28_35;
	unsigned long ist1;
	unsigned long ist2;
	unsigned long ist3;
	unsigned long ist4;
	unsigned long ist5;
	unsigned long ist6;
	unsigned long ist7;
	unsigned long rsv_92_99;
	unsigned short rsv_100_101;
	unsigned short io_map_base_addr;
} tss_t;

__attribute__((__always_inline__))
tss_t *get_tss(void) {
	gdtr_t gdtr={0};
	unsigned short tr=0;
	__asm__ __volatile__("sgdt %0"::"m"(gdtr):"memory");
	__asm__ __volatile__("str %0"::"m"(tr):"memory");
	tssd_t *tssd=(void *)((unsigned long)gdtr.addr+tr);
	return (tss_t *)(0
		| ((long)(tssd->base_addr_0_15))
		| ((long)(tssd->base_addr_16_23)<<16)
		| ((long)(tssd->base_addr_24_31)<<24)
		| ((long)(tssd->base_addr_32_63)<<32)); }
/////////////////////////////////////////////////////
//pg 3244
#define PAT_WB  0x06
#define PAT_WT  0x04
#define PAT_UC_ 0x07
#define PAT_UC  0x00

//pg 2910
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long p:1;
		unsigned long rw:1;
		unsigned long us:1;
		unsigned long pwt:1;
		unsigned long pcd:1;
		unsigned long accessed:1;
		unsigned long dirty:1;
		unsigned long page_size:1;	//can be PAT here for 4kb page :/
		unsigned long global:1;
		unsigned long rsv_9_11:3;
		unsigned long addr:40;		//bits 12 to 51
		unsigned long rsv_52_58:7;
		unsigned long prot_key:4;
		unsigned long nx:1; };
	struct __attribute__((packed)) {
		unsigned long rsv_4kb_0_6:7;
		unsigned long pat_4kb:1;
		unsigned long rsv_4kb_8_11:4;
		unsigned long addr_4kb:40;	//bits 12 to 51
		unsigned long rsv_4kb_52_63:12; };
	struct __attribute__((packed)) {
		unsigned long rsv_1gb_0_11:12;
		unsigned long pat_1gb:1;
		unsigned long rsv_1gb_13_29:17;
		unsigned long addr_1gb:22;	//bits 30 to 51
		unsigned long rsv_1gb_52_63:12; };
	struct __attribute__((packed)) {
		unsigned long rsv_2mb_0_11:12;
		unsigned long pat_2mb:1;
		unsigned long rsv_2mb_13_20:8;
		unsigned long addr_2mb:31;	//bits 21 to 51
		unsigned long rsv_2mb_52_63:12; };
	unsigned long val;
} pse_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long offset_pse:12;
		unsigned long pt_bits:9;	//bits 12 to 20
		unsigned long pd_bits:9;	//bits 21 to 29
		unsigned long pdpt_bits:9;	//bits 30 to 38
		unsigned long pml4_bits:9;	//bits 39 to 47
		unsigned long pml5_bits:9;	//bits 48 to 56
		unsigned long rsv_57_63:7; };
	struct __attribute__((packed)) {
		unsigned long offset_1gb:30;
		unsigned long rsv_30_63:34; };
	struct __attribute__((packed)) {
		unsigned long offset_2mb:21;
		unsigned long rsv_21_63:43; };
	struct __attribute__((packed)) {
		unsigned long offset_4kb:12;
		unsigned long rsv_12_63:52; };
	unsigned long val;
} vaddr_t;

typedef struct {
	pse_t *pml5e_p;
	pse_t *pml4e_p;
	pse_t *pdpte_p;
	pse_t *pde_p;
	pse_t *pte_p;
} vtp_t;

unsigned int
vtp(unsigned long addr, unsigned long *paddr_p, vtp_t *vtp_p) {
	//asm block checks to see if 4 or 5-level paging is enabled
	//if so, moves the cr3 register into the cr3 variable
	//and sets la57_flag to assert whether 4-level or 5-level
	int la57_flag=0;
	pse_t cr3={0};
	__asm__ __volatile__ (
		"mov %%cr0, %%rax;"		//check bit 31 of cr0 (PG flag)
		"test $0x80000000, %%eax;"	//deny request if 0
		"jz vtp_fail;"			//(ie if paging is not enabled)

		"mov $0xc0000080, %%ecx;"	//check bit 8 of ia32_efer (LME flag)
		"rdmsr;"			//deny request if 0
		"test $0x100, %%eax;"		//(module currently can't handle pae paging)
		"jz vtp_fail;"
		
	"vtp_success:\n"
		"mov %%cr3, %0;"
		"mov %%cr4, %%rax;"
		"shr $12, %%rax;"
		"and $1, %%rax;"
		"mov %%eax, %1;"
		"jmp vtp_finish;"
	"vtp_fail:\n"
		"mov $0, %0;"
	"vtp_finish:\n"
	
		: "=r"(cr3.val), "=r"(la57_flag)
		::"rax", "ecx", "edx", "memory");
	if(!cr3.val) {
		return -EOPNOTSUPP; }

	pse_t psentry={0};
	vaddr_t vaddr=(vaddr_t)addr;
	if(vtp_p!=NULL) {
		*vtp_p=(vtp_t){ .pml5e_p=NULL, .pml4e_p=NULL, .pdpte_p=NULL, .pde_p=NULL, .pte_p=NULL }; }

	//pml5e (if applicable)
	if(la57_flag) {			//5-level paging
		if(vtp_p!=NULL) {
			vtp_p->pml5e_p=(void *)phys_to_virt(((unsigned long)cr3.addr<<12)|((unsigned long)vaddr.pml5_bits<<3)); }
		psentry.val=*(unsigned long *)\
			phys_to_virt(((unsigned long)cr3.addr<<12)|((unsigned long)vaddr.pml5_bits<<3));
		if(!psentry.p) {
			return -EFAULT; }}
	else {
		psentry.val=cr3.val; }

	//pml4e
	if(vtp_p!=NULL) {
		vtp_p->pml4e_p=(void *)phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pml4_bits<<3)); }
	psentry.val=*(unsigned long *)\
		phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pml4_bits<<3));
	if(!psentry.p) {
		return -EFAULT; }

	//pdpte
	if(vtp_p!=NULL) {
		vtp_p->pdpte_p=(void *)phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pdpt_bits<<3)); }
	psentry.val=*(unsigned long *)\
		phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pdpt_bits<<3));
	if(psentry.page_size) {	//1GB page
		//bits (51 to 30) | bits (29 to 0)
		*paddr_p=((unsigned long)psentry.addr_1gb<<30)|vaddr.offset_1gb;
		return 0; }
	if(!psentry.p) {
		return -EFAULT; }

	//pde
	if(vtp_p!=NULL) {
		vtp_p->pde_p=(void *)phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pd_bits<<3)); }
	psentry.val=*(unsigned long *)\
		phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pd_bits<<3));
	if(psentry.page_size) {	//2MB page
		//bits (51 to 21) | bits (20 to 0)
		*paddr_p=((unsigned long)psentry.addr_2mb<<21)|vaddr.offset_2mb;
		return 0; }
	if(!psentry.p) {
		return -EFAULT; }

	//pte
	if(vtp_p!=NULL) {
		vtp_p->pte_p=(void *)phys_to_virt(((unsigned long)psentry.addr<<12)|((unsigned long)vaddr.pt_bits<<3)); }
	psentry.val=*(unsigned long *)\
		phys_to_virt(((unsigned long)psentry.addr_4kb<<12)|((unsigned long)vaddr.pt_bits<<3));
	*paddr_p=((unsigned long)psentry.addr_4kb<<12)|vaddr.offset_4kb;
	return 0; }
/////////////////////////////////////////////////////

#endif
