#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "vtx-utilities.h"
#include "x64-utilities.h"

#ifndef __VMCS
#define __VMCS


////////////////////////////////////////////////////////
enum vmcs_encodings {
	VPID =				0x00000000,
	PINV =				0x00000002,	//posted-interrupt notification vector
	EPTP_INDEX =			0x00000004,

	GUEST_ES_SS =			0x00000800,
	GUEST_CS_SS =			0x00000802,
	GUEST_SS_SS =			0x00000804,
	GUEST_DS_SS =			0x00000806,
	GUEST_FS_SS =			0x00000808,
	GUEST_GS_SS =			0x0000080a,
	GUEST_LDTR_SS =			0x0000080c,
	GUEST_TR_SS =			0x0000080e,

	GUEST_INTERRUPT_STATUS =	0x00000810,
	PML_INDEX =			0x00000812,

	HOST_ES_SS =			0x00000c00,
	HOST_CS_SS =			0x00000c02,
	HOST_SS_SS =			0x00000c04,
	HOST_DS_SS =			0x00000c06,
	HOST_FS_SS =			0x00000c08,
	HOST_GS_SS =			0x00000c0a,
	HOST_TR_SS =			0x00000c0c,

	IO_BMP_A_F =			0x00002000,
	IO_BMP_A_H =			0x00002001,
	IO_BMP_B_F =			0x00002002,
	IO_BMP_B_H =			0x00002003,

	MSR_BMP_ADDR_F =		0x00002004,
	MSR_BMP_ADDR_H =		0x00002005,

	EXIT_MSR_STR_ADDR_F =		0x00002006,
	EXIT_MSR_STR_ADDR_H =		0x00002007,
	EXIT_MSR_LD_ADDR_F = 		0x00002008,
	EXIT_MSR_LD_ADDR_H = 		0x00002009,
	ENTRY_MSR_LD_ADDR_F =		0x0000200a,
	ENTRY_MSR_LD_ADDR_H =		0x0000200b,

	EXECUTIVE_VMCS_PTR_F =		0x0000200c,
	EXECUTIVE_VMCS_PTR_H =		0x0000200d,

	PML_ADDR_F =			0x0000200e,
	PML_ADDR_H =			0x0000200f,

	TSC_OFFSET_F =			0x00002010,
	TSC_OFFSET_H =			0x00002011,

	VIRTUAL_APIC_ADDR_F =		0x00002012,
	VIRTUAL_APIC_ADDR_H =		0x00002013,
	APIC_ACCESS_ADDR_F =		0x00002014,
	APIC_ACCESS_ADDR_H =		0x00002015,

	PIDA_F =			0x00002016,	//posted-interrupt descriptor address
	PIDA_H =			0x00002017,	//posted-interrupt descriptor address

	VMFUNC_CTRLS_F =		0x00002018,
	VMFUNC_CTRLS_H =		0x00002019,

	EPTP_F =			0x0000201a,
	EPTP_H =			0x0000201b,

	EOI_EXIT0_F =			0x0000201c,
	EOI_EXIT0_H =			0x0000201d,
	EOI_EXIT1_F =			0x0000201e,
	EOI_EXIT1_H =			0x0000201f,
	EOI_EXIT2_F =			0x00002020,
	EOI_EXIT2_H =			0x00002021,
	EOI_EXIT3_F =			0x00002022,
	EOI_EXIT3_H =			0x00002023,

	EPTP_LIST_ADDR_F =		0x00002024,
	EPTP_LIST_ADDR_H =		0x00002025,

	VMREAD_BMP_ADDR_F =		0x00002026,
	VMREAD_BMP_ADDR_H =		0x00002027,
	VMWRITE_BMP_ADDR_F =		0x00002028,
	VMWRITE_BMP_ADDR_H =		0x00002029,

	VE_INFO_ADDR_F =		0x0000202a,	//virtualization exception
	VE_INFO_ADDR_H =		0x0000202b,	//virtualization exception

	XSS_EXITING_BMP_F =		0x0000202c,
	XSS_EXITING_BMP_H =		0x0000202d,

	ENCLS_EXITING_BMP_F =		0x0000202e,
	ENCLS_EXITING_BMP_H =		0x0000202f,

	SPPT_PTR_F =			0x00002030,	//sub-page-permission-table pointer
	SPPT_PTR_H =			0x00002031,	//sub-page-permission-table pointer

	TSC_MULTIPLIER_F =		0x00002032,
	TSC_MULTIPLIER_H =		0x00002033,

	ENCLV_EXITING_BMP_F =		0x00002036,
	ENCLV_EXITING_BMP_H =		0x00002037,

	GUEST_PADDR_F =			0x00002400,
	GUEST_PADDR_H =			0x00002401,

	VMCS_LINK_PTR_F =		0x00002800,
	VMCS_LINK_PTR_H =		0x00002801,

	GUEST_IA32_DEBUGCTL_F =		0x00002802,
	GUEST_IA32_DEBUGCTL_H =		0x00002803,
	GUEST_IA32_PAT_F =		0x00002804,
	GUEST_IA32_PAT_H =		0x00002805,
	GUEST_IA32_EFER_F =		0x00002806,
	GUEST_IA32_EFER_H =		0x00002807,

	GUEST_IA32_PERF_GLOBAL_CTRL_F =	0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_H =	0x00002809,

	GUEST_PDPTE0_F =		0x0000280a,
	GUEST_PDPTE0_H =		0x0000280b,
	GUEST_PDPTE1_F =		0x0000280c,
	GUEST_PDPTE1_H =		0x0000280d,
	GUEST_PDPTE2_F =		0x0000280e,
	GUEST_PDPTE2_H =		0x0000280f,
	GUEST_PDPTE3_F =		0x00002810,
	GUEST_PDPTE3_H =		0x00002811,
	GUEST_IA32_BNDCFGS_F =		0x00002812,
	GUEST_IA32_BNDCFGS_H =		0x00002813,
	GUEST_IA32_RTIT_CTL_F =		0x00002814,
	GUEST_IA32_RTIT_CTL_H =		0x00002815,
	GUEST_IA32_PKRS_F =		0x00002818,
	GUEST_IA32_PKRS_H =		0x00002819,
	
	HOST_IA32_PAT_F =		0x00002c00,
	HOST_IA32_PAT_H =		0x00002c01,
	HOST_IA32_EFER_F =		0x00002c02,
	HOST_IA32_EFER_H =		0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL_F =	0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_H =	0x00002c05,
	HOST_IA32_PKRS_F =		0x00002c06,
	HOST_IA32_PKRS_H =		0x00002c07,
	
	PIN_BASED_X_CTLS =		0x00004000,
	PRIMARY_CPU_BASED_X_CTLS =	0x00004002,
	EXCEPTION_BMP =			0x00004004,
	PF_ERROR_CODE_MASK =		0x00004006,
	PF_ERROR_CODE_MATCH =		0x00004008,
	CR3_TARGET_COUNT =		0x0000400a,
	EXIT_CTLS =			0x0000400c,
	EXIT_MSR_STR_COUNT =		0x0000400e,
	EXIT_MSR_LD_COUNT =		0x00004010,
	ENTRY_CTLS =			0x00004012,
	ENTRY_MSR_LD_COUNT =		0x00004014,
	ENTRY_INTERRUPTION_INFO =	0x00004016,
	ENTRY_EXCEPTION_ERROR_CODE =	0x00004018,
	ENTRY_INSTRUCTION_LENGTH =	0x0000401a,
	TPR_THRESHOLD =			0x0000401c,
	SECONDARY_CPU_BASED_X_CTLS =	0x0000401e,
	PLE_GAP =			0x00004020,
	PLE_WINDOW =			0x00004022,
	
	VM_INSTRUCTION_ERROR =		0x00004400,
	EXIT_REASON =			0x00004402,
	EXIT_INTERRUPTION_INFO =	0x00004404,
	EXIT_INTERRUPTION_ERROR_CODE =	0x00004406,
	IDT_VECTORING_INFO =		0x00004408,
	IDT_VECTORING_ERROR_CODE =	0x0000440a,
	EXIT_INSTRUCTION_LENGTH =	0x0000440c,
	EXIT_INSTRUCTION_INFO =		0x0000440e,
	
	GUEST_ES_LIMIT =		0x00004800,
	GUEST_CS_LIMIT =		0x00004802,
	GUEST_SS_LIMIT =		0x00004804,
	GUEST_DS_LIMIT =		0x00004806,
	GUEST_FS_LIMIT =		0x00004808,
	GUEST_GS_LIMIT =		0x0000480a,
	GUEST_LDTR_LIMIT =		0x0000480c,
	GUEST_TR_LIMIT =		0x0000480e,
	GUEST_GDTR_LIMIT =		0x00004810,
	GUEST_IDTR_LIMIT =		0x00004812,
	
	GUEST_ES_ACCESS_RIGHTS =	0x00004814,
	GUEST_CS_ACCESS_RIGHTS =	0x00004816,
	GUEST_SS_ACCESS_RIGHTS =	0x00004818,
	GUEST_DS_ACCESS_RIGHTS =	0x0000481a,
	GUEST_FS_ACCESS_RIGHTS =	0x0000481c,
	GUEST_GS_ACCESS_RIGHTS =	0x0000482e,
	GUEST_LDTR_ACCESS_RIGHTS =	0x00004820,
	GUEST_TR_ACCESS_RIGHTS =	0x00004822,
	
	GUEST_INTERRUPTIBILITY_STATE =	0x00004824,
	GUEST_ACTIVITY_STATE =		0x00004826,
	GUEST_SMBASE =			0x00004828,
	GUEST_IA32_SYSENTER_CS =	0x0000482a,
	PREEMPTION_TIMER_VALUE =	0x0000482e,
	
	HOST_IA32_SYSENTER_CS =		0x00004c00,
	
	CR0_GUEST_HOST_MASK =		0x00006000,
	CR4_GUEST_HOST_MASK =		0x00006002,
	CR0_READ_SHADOW =		0x00006004,
	CR4_READ_SHADOW =		0x00006006,
	CR3_TARGET_VALUE_0 =		0x00006008,
	CR3_TARGET_VALUE_1 =		0x0000600a,
	CR3_TARGET_VALUE_2 =		0x0000600c,
	CR3_TARGET_VALUE_3 =		0x0000600e,
	
	EXIT_QUALIFICATION =		0x00006400,
	IO_RCX =			0x00006402,
	IO_RSI =			0x00006404,
	IO_RDI =			0x00006406,
	IO_RIP =			0x00006408,
	GUEST_LINEAR_ADDR =		0x0000640a,
	
	GUEST_CR0 =			0x00006800,
	GUEST_CR3 =			0x00006802,
	GUEST_CR4 =			0x00006804,
	
	GUEST_ES_BASE =			0x00006806,
	GUEST_CS_BASE =			0x00006808,
	GUEST_SS_BASE =			0x0000680a,
	GUEST_DS_BASE =			0x0000680c,
	GUEST_FS_BASE =			0x0000680e,
	GUEST_GS_BASE =			0x00006810,
	GUEST_LDTR_BASE =		0x00006812,
	GUEST_TR_BASE =			0x00006814,
	GUEST_GDTR_BASE =		0x00006816,
	GUEST_IDTR_BASE =		0x00006818,
	
	GUEST_DR7 =			0x0000681a,
	GUEST_RSP =			0x0000681c,
	GUEST_RIP =			0x0000681e,
	GUEST_RFLAGS =			0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS =	0x00006822,
	GUEST_IA32_SYSENTER_ESP =	0x00006824,
	GUEST_IA32_SYSENTER_EIP =	0x00006826,
	GUEST_IA32_S_CET =		0x00006828,
	GUEST_SSP =			0x0000682a,
	GUEST_IA32_ISTA =		0x0000682c,	//interrupt_ssp_table_addr
	
	HOST_CR0 =			0x00006c00,
	HOST_CR3 =			0x00006c02,
	HOST_CR4 =			0x00006c04,
	
	HOST_FS_BASE =			0x00006c06,
	HOST_GS_BASE =			0x00006c08,
	HOST_TR_BASE =			0x00006c0a,
	HOST_GDTR_BASE =		0x00006c0c,
	HOST_IDTR_BASE =		0x00006c0e,
	
	HOST_IA32_SYSENTER_ESP =	0x00006c10,
	HOST_IA32_SYSENTER_EIP =	0x00006c12,
	HOST_RSP =			0x00006c14,
	HOST_RIP =			0x00006c16,
	HOST_IA32_S_CET =		0x00006c18,
	HOST_SSP =			0x00006c1a,
	HOST_IA32_ISTA =		0x00006c1c };	//interrupt_ssp_table_addr

/*#define PRINT_VMCS_ENCODING(X) \
printk("component 0x%08x:\n" \
	       "\tname:\t%s\n" \
	       "\tindex:\t0x%02x\n" \
	       "\ttype:\t%d\n" \
	       "\twidth:\t%d\n", \
	       X, #X, ((vmcs_component_encoding)(unsigned int)(X)).index, \
	       ((vmcs_component_encoding)(unsigned int)(X)).type, ((vmcs_component_encoding)(unsigned int)(X)).width);*/

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned int access_type:1;	//0=full, 1=high
		unsigned int index:9;
		unsigned int type:2;
			#define VMCS_TYPE_CONTROL	0
			#define VMCS_TYPE_EXIT_INFO	1
			#define VMCS_TYPE_GUEST_STATE	2
			#define VMCS_TYPE_HOST_STATE	3
		unsigned int rsv_12:1;		//must be 0
		unsigned int width:2;
			#define VMCS_WIDTH_16		0
			#define VMCS_WIDTH_32		1
			#define VMCS_WIDTH_64		2
			#define VMCS_WIDTH_NATURAL	3
		unsigned int rsv_15_31:17; };	//must be 0
	unsigned int val;
} vmcs_component_encoding;
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
enum basic_vm_exit_reasons {
	ER_EXCEPTION_OR_NMI =	0,
	ER_EXTERNAL_INTERRUPT =	1,
	ER_TRIPLE_FAULT =	2,
	ER_INIT_SIGNAL =	3,
	ER_SIPI =		4,
	ER_IO_SMI =		5,
	ER_OTHER_SMI =		6,
	ER_INTERRUPT_WINDOW =	7,
	ER_NMI_WINDOW =		8,
	ER_TASK_SWITCH =	9,
	ER_CPUID =		10,
	ER_GETSEC =		11,
	ER_HLT =		12,
	ER_INVD =		13,
	ER_INVLPG =		14,
	ER_RDPMC =		15,
	ER_RDTSC =		16,
	ER_RSM =		17,
	ER_VMCALL =		18,
	ER_VMCLEAR =		19,
	ER_VMLAUNCH =		20,
	ER_VMPTRLD =		21,
	ER_VMPTRST =		22,
	ER_VMREAD =		23,
	ER_VMRESUME =		24,
	ER_VMWRITE =		25,
	ER_VMXOFF =		26,
	ER_VMXON =		27,
	ER_CR_ACCESS =		28,
	ER_MOV_DR =		29,
	ER_IO_INSTRUCTION =	30,
	ER_RDMSR =		31,
	ER_WRMSR =		32,
	ER_INVL_GUEST_STATE =	33,	//entry failure
	ER_MSR_LOADING =	34,	//entry failure
	ER_MWAIT =		36,
	ER_MONITOR_TRAP_FLAG =	37,
	ER_MONITOR =		39,
	ER_PAUSE =		40,
	ER_MACHINE_CHECK =	41,	//entry failure
	ER_TPR_BELOW_THESHOLD =	43,
	ER_APIC_ACCESS =	44,
	ER_VIRTUALIZED_EOI =	45,
	ER_GDTR_IDTR_ACCESS =	46,
	ER_LDTR_TR_ACCESS =	47,
	ER_EPT_VIOLATION =	48,
	ER_EPT_MISCONFIG =	49,
	ER_INVEPT =		50,
	ER_RDTSCP =		51,
	ER_PREEMPTION_TIMER =	52,
	ER_INVVPID =		53,
	ER_WBIND =		54,
	ER_XSETBV =		55,
	ER_APIC_WRITE =		56,
	ER_RDRAND =		57,
	ER_INVPCID =		58,
	ER_VMFUNC =		59,
	ER_ENCLS =		60,
	ER_RDSEED =		61,
	ER_PM_LOG_FULL =	62,	//page modification log
	ER_XSAVES =		63,
	ER_XRSTORS =		64,
	ER_SPP_RELATED_EVENT =	66,
	ER_UMWAIT =		67,
	ER_TPAUSE =		68 };
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
typedef struct __attribute__((packed)) {
	unsigned int segment_type:4;
	unsigned int s:1;	//descriptor type. 0=system, 1=code_or_data
	unsigned int dpl:2;
	unsigned int p:1;
	unsigned int rsv_8_11:4;
	unsigned int avl:1;
	unsigned int l:1;	//64 bit mode active (for only CS)
	unsigned int db:1;	//default operation size: 0=16 bit segment, 1=32 bit segment
	unsigned int g:1;	//granularity
	unsigned int unusable:1;
	unsigned int rsv_17_31:15;
} access_rights_t;

typedef struct __attribute__((packed)) {
	unsigned int sti:1;
	unsigned int mov_ss:1;
	unsigned int smi:1;
	unsigned int nmi:1;
	unsigned int enclave_interruption:1;
	unsigned int rsv_5_31:27;	//must be 0
} interruptibility_state_t;

enum activity_state {
	ACTIVE =	0,
	HLT =		1,
	SHUTDOWN =	2,
	WAIT_FOR_SIPI =	3 };

typedef struct __attribute__((packed)) {
	unsigned long b0_b3:4;
	unsigned long rsv_4_11:8;	//must be 0
	unsigned long enabled_bp:1;
	unsigned long rsv_13:1;		//must be 0
	unsigned long bs:1;
	unsigned long rsv_15:1;		//must be 0
	unsigned long rtm:1;
	unsigned long rsv_17_63:47;	//must be 0
} pending_dbg_exceptions_t;

typedef struct __attribute__((packed)) {
	unsigned char rvi;	//rewuesting virtual interrupt
	unsigned char svi;	//servicing virtual interrupt
} guest_interrupt_status_t;

typedef struct {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long dr7;
	unsigned long rsp;
	unsigned long rip;
	unsigned long rflags;
	
	access_rights_t access_rights;

	unsigned short cs_selector;
	unsigned long cs_base;
	unsigned int cs_lim;
	unsigned int cs_access_rights;
	
	unsigned short ss_selector;
	unsigned long ss_base;
	unsigned int ss_lim;
	unsigned int ss_access_rights;
	
	unsigned short ds_selector;
	unsigned long ds_base;
	unsigned int ds_lim;
	unsigned int ds_access_rights;
	
	unsigned short es_selector;
	unsigned long es_base;
	unsigned int es_lim;
	unsigned int es_access_rights;
	
	unsigned short fs_selector;
	unsigned long fs_base;
	unsigned int fs_lim;
	unsigned int fs_access_rights;
	
	unsigned short gs_selector;
	unsigned long gs_base;
	unsigned int gs_lim;
	unsigned int gs_access_rights;
	
	unsigned short ldtr_selector;
	unsigned long ldtr_base;
	unsigned int ldtr_lim;
	unsigned int ldtr_access_rights;
	
	unsigned short tr_selector;
	unsigned long tr_base;
	unsigned int tr_lim;
	unsigned int tr_access_rights;
	
	gdtr_t gdtr;
	idtr_t idtr;
	
	msr_t ia32_debugctl;
	msr_t ia32_sysenter_cs;
	msr_t ia32_sysenter_esp;
	msr_t ia32_sysenter_eip;
	msr_t ia32_perf_global_ctrl;
	msr_t ia32_pat;
	msr_t ia32_efer;
	msr_t ia32_bndcfgs;

	unsigned int smbase;

	////////////////////////////////////////////////
	
	unsigned int activity_state;
		//active:	0
		//hlt:		1
		//shutdown:	2
		//waitforsipi:	3
		//active, HLT, shutdown, wait-for-sipi
	
	interruptibility_state_t interruptibility_state;
	
	pending_dbg_exceptions_t pending_dbg_exceptions;
	
	unsigned long vmcs_link_pointer;	//for vmcs shadowing
	unsigned int preemption_timer;
	unsigned long pdpte0;
	unsigned long pdpte1;
	unsigned long pdpte2;
	unsigned long pdpte3;

	guest_interrupt_status_t guest_interrupt_status;
	
	unsigned short pml_index;
} guest_state_area;




typedef struct {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long rsp;
	unsigned long rip;
	
	access_rights_t access_rights;

	unsigned short cs_selector;
	unsigned short ss_selector;
	unsigned short ds_selector;
	unsigned short es_selector;
	
	unsigned short fs_selector;
	unsigned long fs_base;
	
	unsigned short gs_selector;
	unsigned long gs_base;
	
	unsigned short tr_selector;
	unsigned long tr_base;
	
	unsigned long gdtr_base;
	unsigned long idtr_base;
	
	msr_t ia32_sysenter_cs;
	msr_t ia32_sysenter_esp;
	msr_t ia32_sysenter_eip;
	msr_t ia32_perf_global_ctrl;
	msr_t ia32_pat;
	msr_t ia32_efer;
} host_state_area;




//for reserved bits, consult
//ia32_vmx_pinbased_ctls
//ia32_vmx_true_pinbased_ctls
typedef struct __attribute__((packed)) {
	unsigned int external_interrupt_exiting:1;
	unsigned int rsv_1_2:2;
	unsigned int nmi_exiting:1;
	unsigned int rsv_4:1;
	unsigned int virtual_nmis:1;
	unsigned int preemption_timer_active:1;
	unsigned int process_posted_interrupts:1;
	unsigned int rsv_8_31:24;
} pin_based_execution_controls_t;

//for reserved bits, consult
//ia32_vmx_procbased_ctls
//ia32_vmx_true_procbased_ctls
typedef struct __attribute__((packed)) {
	unsigned int rsv_0_1:2;
	unsigned int interrupt_window_exiting:1;
	unsigned int use_tsc_offsetting:1;
	unsigned int rsv_4_6:3;
	unsigned int hlt_exiting:1;
	unsigned int rsv_8:1;
	unsigned int invlpg_exiting:1;
	unsigned int mwait_exiting:1;
	unsigned int rdpmc_exiting:1;
	unsigned int rdtsc_exiting:1;
	unsigned int rsv_13_14:2;
	unsigned int cr3_load_exiting:1;
	unsigned int cr3_store_exiting:1;
	unsigned int rsv_17_18:2;
	unsigned int cr8_load_exiting:1;
	unsigned int cr8_store_exiting:1;
	unsigned int use_tpr_shadow:1;
	unsigned int nmi_window_exiting:1;
	unsigned int mov_dr_exiting:1;
	unsigned int unconditional_io_exiting:1;
	unsigned int use_io_bitmaps:1;
	unsigned int rsv_26:1;
	unsigned int monitor_trap_flag:1;
	unsigned int use_msr_bitmaps:1;
	unsigned int monitor_exiting:1;
	unsigned int pause_exiting:1;
	unsigned int activate_secondary_controls:1;
} primary_cpu_based_execution_controls_t;

//all bits reserved to zero
//for bits settable to 1, consult
//ia32_vmx_procbased_ctls2
typedef struct __attribute__((packed)) {
	unsigned int virtualize_apic_accesses:1;
	unsigned int enable_ept:1;
	unsigned int descriptor_table_exiting:1;
	unsigned int enable_rdtscp:1;
	unsigned int virtualize_x2apic_mode:1;
	unsigned int enable_vpid:1;
	unsigned int wbinvd_exiting:1;
	unsigned int unrestricted_guest:1;
	unsigned int apic_register_virtualization:1;
	unsigned int virtual_interrupt_delivery:1;
	unsigned int pause_loop_exiting:1;
	unsigned int rdrand_exiting:1;
	unsigned int enable_invpcid:1;
	unsigned int enable_vm_functions:1;
	unsigned int vmcs_shadowing:1;
	unsigned int enable_encls_exiting:1;
	unsigned int rdseed_exiting:1;
	unsigned int enable_pml:1;
	unsigned int ept_violation_ve:1;
	unsigned int conceal_vmx_nonroot:1;
	unsigned int enable_xsaves_srstors:1;
	unsigned int rsv_21:1;
	unsigned int mode_based_x_control_ept:1;
	unsigned int rsv_23_24:2;
	unsigned int use_tsc_scaling:1;
	unsigned int rsv_26_31:6;
} secondary_cpu_based_execution_controls_t;

typedef struct __attribute__((packed)) {
	unsigned int zd:1;
	unsigned int single_step:1;
	unsigned int nmi:1;
	unsigned int bp:1;
	unsigned int overflow:1;
	unsigned int bounds:1;
	unsigned int invalid_opcode:1;
	unsigned int coprocessor_not_available:1;
	unsigned int double_fault:1;
	unsigned int rsv_9:1;
	unsigned int invalid_tss:1;
	unsigned int segment_not_present:1;
	unsigned int stack_fault:1;
	unsigned int gp:1;
	unsigned int pf:1;
	unsigned int rsv_15:1;
	unsigned int math_fault:1;
	unsigned int alignment_check:1;
	unsigned int machine_check:1;
	unsigned int simd_fp_exception:1;
	unsigned int ve:1;
	unsigned int control_protection_exception:1;
	unsigned int rsv_22_31:10;
} exception_bitmap_t;

//for reserved bits, consult
//ia32_vmx_vmfunc
//all reserved bits reserved to 0
typedef struct __attribute__((packed)) {
	unsigned long eptp_switching:1;
	unsigned long rsv_1_63:63;
} vm_function_controls_t;

typedef struct {
	
	pin_based_execution_controls_t pin_based_execution_controls;
	primary_cpu_based_execution_controls_t primary_cpu_based_execution_controls;
	secondary_cpu_based_execution_controls_t secondary_cpu_based_execution_controls;
	exception_bitmap_t exception_bitmap;

	struct {
		unsigned long io_bitmap_a;	//ports 0000 to 7fff
		unsigned long bitmap_a_paddr;
		unsigned long io_bitmap_b;	//ports 8000 to ffff
		unsigned long bitmap_b_paddr; }
		io_bitmap_addrs;

	struct {
		unsigned long tsc_offset;
		unsigned long tsc_multiplier; }
		tsc_fields;

	struct {
		unsigned long cr0_mask;
		unsigned long cr0_shadow;
		unsigned long cr4_mask;
		unsigned long cr4_shadow; }
		cr_masks_and_shadows;

	//read ia32_vmx_misc for supported count
	struct {
		unsigned int cr3_target_count;
		unsigned long cr3_target_0;
		unsigned long cr3_target_1;
		unsigned long cr3_target_2;
		unsigned long cr3_target_3; }
		cr3_target_controls;

	struct {
		unsigned long apic_access_page;
		unsigned long apic_access_paddr;

		unsigned long virtual_apic_page;
		unsigned long virtual_apic_paddr;

		unsigned int tpr_threshold;

		unsigned long eoi_exit0;
		unsigned long eoi_exit1;
		unsigned long eoi_exit2;
		unsigned long eoi_exit3;

		unsigned short posted_interrupt_notification_vector;
		unsigned long posted_interrupt_descriptor_addr; }
		apic_virtualization_controls;

	struct {
		//read bitmap for low msrs	00000000 to 00001fff
		//read bitmap for high msrs	c0000000 to c0001fff
		//write bitmap for low msrs
		//write bitmap for high msrs
		unsigned long msr_bitmap_addr;
		unsigned long msr_bitmap_paddr; }
		msr_bitmap_controls;

	unsigned long executive_vmcs_pointer;

	//consult ia32_vmx_ept_vpid_cap
	//to determine whether accessed/
	//dirty flags are supported
	eptp_t eptp;

	unsigned short virtual_processor_identifier;

	struct {
		unsigned int ple_gap;
		unsigned int ple_window; }
	pause_loop_exiting_controls;

	vm_function_controls_t vm_function_controls;

	struct {
		unsigned long vmread_bitmap_addr;
		unsigned long vmread_bitmap_paddr;
		unsigned long vmwrite_bitmap_addr;
		unsigned long vmwrite_bitmap_paddr; }
	vmcs_shadowing_bitmaps;

	unsigned long encls_exiting_bitmap;
	
	unsigned long page_modification_log;			//paddr?
	
	struct {
		unsigned long virtualization_exception_info_area;
		unsigned long virtualization_exception_info_paddr;
		unsigned short eptp_index; }
	virtualization_exception_controls;
	
	unsigned long xss_exiting_bitmap;
} vm_execution_controls;






//for reserved bits, consult
//ia32_vmx_exit_ctls
//ia32_vmx_true_exit_ctls
typedef struct __attribute__((packed)) {
	unsigned int rsv_0_1:2;
	unsigned int save_dbg_controls:1;
	unsigned int rsv_3_8:6;
	unsigned int host_addr_space_size:1;
	unsigned int rsv_10_11:2;
	unsigned int load_ia32_perf_global_ctrl:1;
	unsigned int rsv_13_14:2;
	unsigned int acknowledge_interrupt:1;
	unsigned int rsv_16_17:2;
	unsigned int save_ia32_pat:1;
	unsigned int load_ia32_pat:1;
	unsigned int save_ia32_efer:1;
	unsigned int load_ia32_efer:1;
	unsigned int save_preemption_timer:1;
	unsigned int clear_ia32_bndcfgs:1;
	unsigned int conceal_vm_exits:1;
	unsigned int rsv_25_31:7;
} vm_exit_controls_t;

typedef struct {
	vm_exit_controls_t vm_exit_controls;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int msr_index;
			unsigned int rsv_32_63;
			unsigned long msr_data; }
			msr_entry;
		//ia32_vmx_misc gives maximum supported count
		//section 27.4
		unsigned int msr_store_count;
		unsigned long msr_store_addr;
		unsigned long msr_store_paddr;
		
		//section 27.6
		unsigned int msr_load_count;
		unsigned long msr_load_addr;
		unsigned long msr_load_paddr;
	} msr_entry_controls;
} vm_exit_control_fields;


//for reserved bits, consult
//ia32_vmx_entry_ctls
//ia32_vmx_true_entry_ctls
typedef struct __attribute__((packed)) {
	unsigned int rsv_0_1:2;
	unsigned int load_dbg_controls:1;
	unsigned int rsv_3_8:6;
	unsigned int ia_32e_mode_guest:1;
	unsigned int entry_to_smm:1;
	unsigned int deactivate_dual_monitor_treatment:1;
	unsigned int rsv_12:1;
	unsigned int load_ia32_perf_global_ctrl:1;
	unsigned int load_ia32_pat:1;
	unsigned int load_ia32_efer:1;
	unsigned int load_ia32_bndcfgs:1;
	unsigned int conceal_vm_entries:1;
	unsigned int rsv_18_31:14;
} vm_entry_controls_t;

typedef struct {
	vm_entry_controls_t vm_entry_controls;
	
	struct {
		//ia32_vmx_misc gives maximum supported count
		//section 26.4
		unsigned int msr_load_count;
		unsigned long msr_load_addr;
		unsigned long msr_load_paddr;
	} msr_entry_controls;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int vector:8;
			unsigned int type:3;
				//external interrupt:	0
				//nmi:			2
				//hardware exception:	3
				//software interrupt:	4
				//privilege sw except:	5
				//software exception:	6
				//other event:		7
			unsigned int deliver_error_code:1;
			unsigned int rsv_12_30:19;	//set to 0??
			unsigned int valid:1; }
			vm_entry_interruption_info;
		
		unsigned int vm_entry_exception_error_code;
		unsigned int vm_entry_instruction_length;
	} event_injection_entry_controls;
} vm_entry_control_fields;





typedef struct __attribute__((packed)) {
	unsigned int basic_exit_reason:16;	//appendix C
	unsigned int rsv_16_26:11;	//must be 0
	unsigned int enclave_incident:1;
	unsigned int pending_mtf_vm_exit:1;
	unsigned int vmx_root_exit:1;
	unsigned int rsv_30:1;		//must be 0
	unsigned int vm_entry_failure:1;
} exit_reason_t;

typedef struct __attribute__((packed)) {
	unsigned int vector:8;
	unsigned int type:3;
		//external interrupt:	0
		//nmi:			2
		//hardware exception:	3
		//software exception:	6
	unsigned int error_code_valid:1;
	unsigned int iret_nmi_unblocking:1;
	unsigned int rsv_13_30:18;	//set to 0
	unsigned int valid:1;
} vm_exit_interruption_info_t;

typedef struct __attribute__((packed)) {
	unsigned int vector:8;
	unsigned int type:3;
		//external interrupt:	0
		//nmi:			2
		//hardware exception:	3
		//software interrupt:	4
		//privilege sw except:	5
		//software exception:	6
	unsigned int error_code_valid:1;
	unsigned int rsv_12_30:19;	//set to 0
	unsigned int valid:1;
} idt_vectoring_info_t;

typedef struct {
	struct {
		exit_reason_t exit_reason;
		unsigned long exit_qualification;	//section 27.2.1
		unsigned long guest_linear_addr;
		unsigned long guest_paddr;
	} basic_vm_exit_info;
	
	struct {
		vm_exit_interruption_info_t vm_exit_interruption_info;

		unsigned int interruption_error_code;
	} vector_vm_exit_info;
	
	struct {
		idt_vectoring_info_t idt_vectoring_info;
		unsigned int idt_vectoring_error_code;
	} event_delivery_vm_exit_info;
	
	struct {
		unsigned int instruction_length;
		unsigned int instruction_info;	//27.2.4
		
		unsigned long io_rcx;
		unsigned long io_rsi;
		unsigned long io_rdi;
		unsigned long io_rip;
	} instruction_execution_vm_exit_info;
	
	unsigned int vm_instruction_error_field;
} vm_exit_information_fields;

////////////////////////////////////////////////////////


////////////////////////////////////////////////////////
//////////////////////////////
//write ia32_vmx_basic.revision_identifier
//disable shadow vmcs (bit 31)
//check ia32_vmx_ept_vpid_cap for accessed/dirty
//check bit 55 of ia32_vmx_basic to see
//	if true_..._ctls are allowed
//vmfunc rsved bits
//////////////////////////////

//assumes vpcs already current
/*int initialize_vpcs(void) {
	msr_t msr;
	lhf_t lhf;
	
	
	//////////////////////
	//checks on vmx ctls
	PIN_BASED_X_CTLS;	//2 MSRS
	PRIMARY_CPU_BASED_X_CTLS;	//2 MSRS
	if(primarycpuctls allow secondary) {
		SECONDARY_CPU_BASED_X_CTLS; }	//1 MSR, reserved bits cleared
	CR3_TARGET_COUNT<=4;	//ia32_vmx_misc
	if(use_io_bitmaps) {
		IO_BMP_A_F, IO_BMP_B_F page aligned; }
	if(use_msr_bitmaps) {
		MSR_BMP_ADDR_F page aligned; }
	if(!use_tpr_shadow) {
		!virtualize_x2apic_mode, !apic_register_virtualization, !virtual_interrupt_delivery; }
	if(enable_ept) {
		...;
		check ia32_vmc_ept_vpid_cap before setting accessed_dirty!; }
	
	EXIT_CTLS;	//2 msrs?
	if(!activate_vmx_preemption_timer) {
		!save_vmx_preemption_timer_value; }
	if(msr_store_count) {
		//? ia32_lstar
		must have !(msr_str_addr&0xffff); }
	VMWRITE(0x50, HOST_CR0, lhf);
	
	ENTRY_CTLS;	//2 msrs?
	interruption information field;
	exception error code;
	entry instruction length;
	if(valid bit) { ...; }
	if(msr_load_count) {
		//?ia32_lstar
		must have !(msr_ld_addr&0xffff); }
	
	HOST_CR0, HOST_CR4;	//vmx_cr_fixed_bits
	HOST_CR3;	//bits beyond physical address width must be 0
	IA32_SYSENTER_ESP, IA32_SYSENTER_EIP;	//canonical address
	segment selectors;
	segment base: ia32_gs_base, ia32_kernel_gs_base, ia32_fs_base;
	
	address space size checks;
	
	GUEST_CR0, GUEST_CR4;	//vmx_cr_fixed_bits
	
	
	return 0; }*/
////////////////////////////////////////////////////////

#endif
