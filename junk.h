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
	VPID =				            0x00000000,
	PINV =				            0x00000002,	//posted-interrupt notification vector
	EPTP_INDEX =			        0x00000004,

	GUEST_ES_SELECTOR =		        0x00000800,
	GUEST_CS_SELECTOR =		        0x00000802,
	GUEST_SS_SELECTOR =		        0x00000804,
	GUEST_DS_SELECTOR =		        0x00000806,
	GUEST_FS_SELECTOR =		        0x00000808,
	GUEST_GS_SELECTOR =		        0x0000080a,
	GUEST_LDTR_SELECTOR =	        0x0000080c,
	GUEST_TR_SELECTOR =		        0x0000080e,

	GUEST_INTERRUPT_STATUS =        0x00000810,
	PML_INDEX =			            0x00000812,

	HOST_ES_SELECTOR =		        0x00000c00,
	HOST_CS_SELECTOR =		        0x00000c02,
	HOST_SS_SELECTOR =		        0x00000c04,
	HOST_DS_SELECTOR =		        0x00000c06,
	HOST_FS_SELECTOR =		        0x00000c08,
	HOST_GS_SELECTOR =		        0x00000c0a,
	HOST_TR_SELECTOR =		        0x00000c0c,

	IO_BMP_A_F =			        0x00002000,
	IO_BMP_A_H =			        0x00002001,
	IO_BMP_B_F =			        0x00002002,
	IO_BMP_B_H =			        0x00002003,

	MSR_BMP_ADDR_F =		        0x00002004,
	MSR_BMP_ADDR_H =		        0x00002005,

	EXIT_MSR_STR_ADDR_F =		    0x00002006,
	EXIT_MSR_STR_ADDR_H =		    0x00002007,
	EXIT_MSR_LD_ADDR_F = 		    0x00002008,
	EXIT_MSR_LD_ADDR_H = 		    0x00002009,
	ENTRY_MSR_LD_ADDR_F =		    0x0000200a,
	ENTRY_MSR_LD_ADDR_H =		    0x0000200b,

	EXECUTIVE_VMCS_PTR_F =		    0x0000200c,
	EXECUTIVE_VMCS_PTR_H =		    0x0000200d,

	PML_ADDR_F =			        0x0000200e,
	PML_ADDR_H =			        0x0000200f,

	TSC_OFFSET_F =			        0x00002010,
	TSC_OFFSET_H =			        0x00002011,

	VIRTUAL_APIC_ADDR_F =		    0x00002012,
	VIRTUAL_APIC_ADDR_H =		    0x00002013,
	APIC_ACCESS_ADDR_F =		    0x00002014,
	APIC_ACCESS_ADDR_H =		    0x00002015,

	PIDA_F =			            0x00002016,	//posted-interrupt descriptor address
	PIDA_H =			            0x00002017,	//posted-interrupt descriptor address

	VMFUNC_CTRLS_F =		        0x00002018,
	VMFUNC_CTRLS_H =		        0x00002019,

	EPTP_F =			            0x0000201a,
	EPTP_H =			            0x0000201b,

	EOI_EXIT0_F =			        0x0000201c,
	EOI_EXIT0_H =			        0x0000201d,
	EOI_EXIT1_F =			        0x0000201e,
	EOI_EXIT1_H =			        0x0000201f,
	EOI_EXIT2_F =			        0x00002020,
	EOI_EXIT2_H =			        0x00002021,
	EOI_EXIT3_F =			        0x00002022,
	EOI_EXIT3_H =			        0x00002023,

	EPTP_LIST_ADDR_F =		        0x00002024,
	EPTP_LIST_ADDR_H =		        0x00002025,

	VMREAD_BMP_ADDR_F =		        0x00002026,
	VMREAD_BMP_ADDR_H =		        0x00002027,
	VMWRITE_BMP_ADDR_F =		    0x00002028,
	VMWRITE_BMP_ADDR_H =		    0x00002029,

	VE_INFO_ADDR_F =		        0x0000202a,	//virtualization exception
	VE_INFO_ADDR_H =		        0x0000202b,	//virtualization exception

	XSS_EXITING_BMP_F =		        0x0000202c,
	XSS_EXITING_BMP_H =		        0x0000202d,

	ENCLS_EXITING_BMP_F =		    0x0000202e,
	ENCLS_EXITING_BMP_H =		    0x0000202f,

	SPPT_PTR_F =			        0x00002030,	//sub-page-permission-table pointer
	SPPT_PTR_H =			        0x00002031,	//sub-page-permission-table pointer

	TSC_MULTIPLIER_F =		        0x00002032,
	TSC_MULTIPLIER_H =		        0x00002033,

	ENCLV_EXITING_BMP_F =		    0x00002036,
	ENCLV_EXITING_BMP_H =		    0x00002037,

	GUEST_PADDR_F =			        0x00002400,
	GUEST_PADDR_H =			        0x00002401,

	VMCS_LINK_PTR_F =		        0x00002800,
	VMCS_LINK_PTR_H =		        0x00002801,

	GUEST_IA32_DEBUGCTL_F =		    0x00002802,
	GUEST_IA32_DEBUGCTL_H =		    0x00002803,
	GUEST_IA32_PAT_F =		        0x00002804,
	GUEST_IA32_PAT_H =		        0x00002805,
	GUEST_IA32_EFER_F =		        0x00002806,
	GUEST_IA32_EFER_H =		        0x00002807,

	GUEST_IA32_PERF_GLOBAL_CTRL_F =	0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_H =	0x00002809,

	GUEST_PDPTE0_F =		        0x0000280a,
	GUEST_PDPTE0_H =		        0x0000280b,
	GUEST_PDPTE1_F =		        0x0000280c,
	GUEST_PDPTE1_H =		        0x0000280d,
	GUEST_PDPTE2_F =		        0x0000280e,
	GUEST_PDPTE2_H =		        0x0000280f,
	GUEST_PDPTE3_F =		        0x00002810,
	GUEST_PDPTE3_H =		        0x00002811,
	GUEST_IA32_BNDCFGS_F =		    0x00002812,
	GUEST_IA32_BNDCFGS_H =		    0x00002813,
	GUEST_IA32_RTIT_CTL_F =		    0x00002814,
	GUEST_IA32_RTIT_CTL_H =		    0x00002815,
	GUEST_IA32_PKRS_F =		        0x00002818,
	GUEST_IA32_PKRS_H =		        0x00002819,
	
	HOST_IA32_PAT_F =		        0x00002c00,
	HOST_IA32_PAT_H =		        0x00002c01,
	HOST_IA32_EFER_F =		        0x00002c02,
	HOST_IA32_EFER_H =		        0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL_F =	0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_H =	0x00002c05,
	HOST_IA32_PKRS_F =		        0x00002c06,
	HOST_IA32_PKRS_H =		        0x00002c07,
	
	PIN_BASED_X_CTLS =		        0x00004000,
	PRIMARY_CPU_BASED_X_CTLS =	    0x00004002,
	EXCEPTION_BMP =			        0x00004004,
	PF_ERROR_CODE_MASK =		    0x00004006,
	PF_ERROR_CODE_MATCH =		    0x00004008,
	CR3_TARGET_COUNT =		        0x0000400a,
	EXIT_CTLS =			            0x0000400c,
	EXIT_MSR_STR_COUNT =		    0x0000400e,
	EXIT_MSR_LD_COUNT =		        0x00004010,
	ENTRY_CTLS =			        0x00004012,
	ENTRY_MSR_LD_COUNT =		    0x00004014,
	ENTRY_INTERRUPTION_INFO =	    0x00004016,
	ENTRY_EXCEPTION_ERROR_CODE =	0x00004018,
	ENTRY_INSTRUCTION_LENGTH =	    0x0000401a,
	TPR_THRESHOLD =			        0x0000401c,
	SECONDARY_CPU_BASED_X_CTLS =	0x0000401e,
	PLE_GAP =			            0x00004020,
	PLE_WINDOW =			        0x00004022,
	
	VM_INSTRUCTION_ERROR =		    0x00004400,
	EXIT_REASON =			        0x00004402,
	EXIT_INTERRUPTION_INFO =	    0x00004404,
	EXIT_INTERRUPTION_ERROR_CODE =	0x00004406,
	IDT_VECTORING_INFO =		    0x00004408,
	IDT_VECTORING_ERROR_CODE =	    0x0000440a,
	EXIT_INSTRUCTION_LENGTH =	    0x0000440c,
	EXIT_INSTRUCTION_INFO =		    0x0000440e,
	
	GUEST_ES_LIMIT =		        0x00004800,
	GUEST_CS_LIMIT =		        0x00004802,
	GUEST_SS_LIMIT =		        0x00004804,
	GUEST_DS_LIMIT =		        0x00004806,
	GUEST_FS_LIMIT =		        0x00004808,
	GUEST_GS_LIMIT =		        0x0000480a,
	GUEST_LDTR_LIMIT =		        0x0000480c,
	GUEST_TR_LIMIT =		        0x0000480e,
	GUEST_GDTR_LIMIT =		        0x00004810,
	GUEST_IDTR_LIMIT =		        0x00004812,
	
	GUEST_ES_ACCESS_RIGHTS =	    0x00004814,
	GUEST_CS_ACCESS_RIGHTS =	    0x00004816,
	GUEST_SS_ACCESS_RIGHTS =	    0x00004818,
	GUEST_DS_ACCESS_RIGHTS =	    0x0000481a,
	GUEST_FS_ACCESS_RIGHTS =	    0x0000481c,
	GUEST_GS_ACCESS_RIGHTS =	    0x0000482e,
	GUEST_LDTR_ACCESS_RIGHTS =	    0x00004820,
	GUEST_TR_ACCESS_RIGHTS =	    0x00004822,
	
	GUEST_INTERRUPTIBILITY_STATE =	0x00004824,
	GUEST_ACTIVITY_STATE =		    0x00004826,
	GUEST_SMBASE =			        0x00004828,
	GUEST_IA32_SYSENTER_CS =	    0x0000482a,
	PREEMPTION_TIMER_VALUE =	    0x0000482e,
	
	HOST_IA32_SYSENTER_CS =		    0x00004c00,
	
	CR0_GUEST_HOST_MASK =		    0x00006000,
	CR4_GUEST_HOST_MASK =		    0x00006002,
	CR0_READ_SHADOW =		        0x00006004,
	CR4_READ_SHADOW =		        0x00006006,
	CR3_TARGET_VALUE_0 =		    0x00006008,
	CR3_TARGET_VALUE_1 =		    0x0000600a,
	CR3_TARGET_VALUE_2 =		    0x0000600c,
	CR3_TARGET_VALUE_3 =		    0x0000600e,
	
	EXIT_QUALIFICATION =		    0x00006400,
	IO_RCX =			            0x00006402,
	IO_RSI =			            0x00006404,
	IO_RDI =			            0x00006406,
	IO_RIP =			            0x00006408,
	GUEST_LINEAR_ADDR =		        0x0000640a,
	
	GUEST_CR0 =			            0x00006800,
	GUEST_CR3 =			            0x00006802,
	GUEST_CR4 =			            0x00006804,
	
	GUEST_ES_BASE =			        0x00006806,
	GUEST_CS_BASE =			        0x00006808,
	GUEST_SS_BASE =			        0x0000680a,
	GUEST_DS_BASE =			        0x0000680c,
	GUEST_FS_BASE =			        0x0000680e,
	GUEST_GS_BASE =			        0x00006810,
	GUEST_LDTR_BASE =		        0x00006812,
	GUEST_TR_BASE =			        0x00006814,
	GUEST_GDTR_BASE =		        0x00006816,
	GUEST_IDTR_BASE =		        0x00006818,
	
	GUEST_DR7 =			            0x0000681a,
	GUEST_RSP =			            0x0000681c,
	GUEST_RIP =			            0x0000681e,
	GUEST_RFLAGS =			        0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS =	0x00006822,
	GUEST_IA32_SYSENTER_ESP =	    0x00006824,
	GUEST_IA32_SYSENTER_EIP =	    0x00006826,
	GUEST_IA32_S_CET =		        0x00006828,
	GUEST_SSP =			            0x0000682a,
	GUEST_IA32_ISTA =		        0x0000682c,	//interrupt_ssp_table_addr
	
	HOST_CR0 =			            0x00006c00,
	HOST_CR3 =			            0x00006c02,
	HOST_CR4 =			            0x00006c04,
	
	HOST_FS_BASE =			        0x00006c06,
	HOST_GS_BASE =			        0x00006c08,
	HOST_TR_BASE =			        0x00006c0a,
	HOST_GDTR_BASE =		        0x00006c0c,
	HOST_IDTR_BASE =		        0x00006c0e,
	
	HOST_IA32_SYSENTER_ESP =	    0x00006c10,
	HOST_IA32_SYSENTER_EIP =	    0x00006c12,
	HOST_RSP =			            0x00006c14,
	HOST_RIP =			            0x00006c16,
	HOST_IA32_S_CET =		        0x00006c18,
	HOST_SSP =			            0x00006c1a,
	HOST_IA32_ISTA =		        0x00006c1c };	//interrupt_ssp_table_addr

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
//lhf for lower half of rflags
//faster/better practice than
//pushf/popf when possible
#define EC_VMWRITE(src, code, lhf, error_code)                                      \
    __asm__ __volatile__(                                                           \
        "vmwrite %1, %2;"                                                           \
        "lahf;"                                                                     \
        "shr $8, %%rax;"                                                            \
        "movb %%al, %0;"                                                            \
        :"=r"(lhf.val)                                                              \
        :"r"((long)(src)),                                                          \
         "r"((long)(code))                                                          \
        :"rax", "memory");                                                          \
    if(!VMsucceed(lhf)) {                                                           \
        if(VMfailValid(lhf)) {                                                      \
            VMREAD(error_code, VM_INSTRUCTION_ERROR, lhf);                          \
            printk("[*]  vmwrite failed with error code %ld\n\n", error_code); }    \
        else if(VMfailInvalid(lhf)) {                                               \
            printk("[*]  %s failed with invalid region\n\n", #instruction); }       \
        return -EINVAL; }

#define GET_ACCESS_RIGHTS(access_rights, selector, gdt_base)                                \
if(!selector) {                                                                             \
	access_rights.val=0;                                                                    \
	access_rights.unusable=1; }                                                             \
else {                                                                                      \
	__asm__ __volatile__("lar %%ax, %%eax":"=a"(access_rights.val):"a"(selector):"memory"); \
	access_rights.val>>=8;                                                                  \
	access_rights.rsv_8_11=0;                                                               \
	access_rights.rsv_17_31=0; }                                                            \
printk("[**]\trights:\t0x%x\n", access_rights.val)
	
#define GET_LIM_VAL(lim, selector, gdt_base)                                    \
if(!selector) {                                                                 \
	lim=0; }                                                                    \
else {                                                                          \
	__asm__ __volatile__("lsl %%ax, %%rax":"=a"(lim):"a"(selector):"memory"); } \
printk("[**]\tlim:\t0x%x\n", lim)
	
#define GET_BASE(base, selector, gdt_base)                          \
if(!selector) {                                                     \
	base=0; }                                                       \
else {                                                              \
	base=0                                                          \
		| (*(unsigned short *)(gdt_base+selector+2))                \
		| ((*(unsigned int *)(gdt_base+selector+4))&0xff)<<16       \
		| ((*(unsigned int *)(gdt_base+selector+4))&0xff000000); }  \
printk("[**]\tbase:\t0x%lx\n", base)

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
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
		unsigned int rsv_17_31:15; };
	unsigned int val;
} access_rights_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned int external_interrupt_exiting:1;
		unsigned int rsv_1_2:2;
		unsigned int nmi_exiting:1;
		unsigned int rsv_4:1;
		unsigned int virtual_nmis:1;
		unsigned int preemption_timer_active:1;
		unsigned int process_posted_interrupts:1;
		unsigned int rsv_8_31:24; };
	unsigned int val;
} pin_based_execution_controls_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
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
		unsigned int activate_secondary_controls:1; };
	unsigned int val;
} primary_cpu_based_execution_controls_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
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
		unsigned int rsv_26_31:6; };
	unsigned int val;
} secondary_cpu_based_execution_controls_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
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
		unsigned int rsv_25_31:7; };
	unsigned int val;
} vm_exit_controls_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
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
		unsigned int rsv_18_31:14; };
	unsigned int val;
} vm_entry_controls_t;


//assumes vmcs already current
int initialize_vmcs(unsigned long guest_rip, unsigned long host_rip, unsigned long guest_rsp, unsigned long host_rsp) {
	printk("[*]  initializing vmcs control fields\n");
	
	///////////////////////////
	
	msr_t msr;
	lhf_t lhf;  //lower half of rflags
	unsigned long error_code;
	
	pin_based_execution_controls_t pin_x_ctls;
	primary_cpu_based_execution_controls_t pri_cpu_x_ctls;
	secondary_cpu_based_execution_controls_t sec_cpu_x_ctls;
	vm_exit_controls_t exit_ctls;
	vm_entry_controls_t entry_ctls;
    
    ///////////////////////////
	
	pin_x_ctls.val=0;
	
	pri_cpu_x_ctls.val=0;
	pri_cpu_x_ctls.rdtsc_exiting=1;
	
	sec_cpu_x_ctls.val=0;
	
	exit_ctls.val=0;
	exit_ctls.host_addr_space_size=1;
	
	entry_ctls.val=0;
	entry_ctls.ia_32e_mode_guest=1;
    
	//////////////////////////

	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] ia32_vmx_basic:\t\t\t0x%lx\n", msr.val);
	int true_flag=msr.vmx_basic.vmx_controls_clear;
	printk("[**] %susing TRUE ctl msrs\n", true_flag ? "":"not ");
	
	READ_MSR(msr, true_flag ? IA32_VMX_TRUE_PINBASED_CTLS:IA32_VMX_PINBASED_CTLS);
	pin_x_ctls.val|=msr.vmx_ctls.allowed_zeroes;
	printk("[**] pinbased controls:\t\t\t0x%08x\n", pin_x_ctls.val);
	if( (pin_x_ctls.val & msr.vmx_ctls.allowed_ones)!=pin_x_ctls.val ) {
		printk("[*]  unsupported bit set\n\n");
		return -EINVAL; }
	EC_VMWRITE(pin_x_ctls.val, PIN_BASED_X_CTLS, lhf, error_code);
	
	READ_MSR(msr, true_flag ? IA32_VMX_TRUE_PROCBASED_CTLS:IA32_VMX_PROCBASED_CTLS);
	pri_cpu_x_ctls.val|=msr.vmx_ctls.allowed_zeroes;
	printk("[**] primary cpu based controls:\t0x%08x\n", pri_cpu_x_ctls.val);
	if( (pri_cpu_x_ctls.val & msr.vmx_ctls.allowed_ones)!=pri_cpu_x_ctls.val ) {
		printk("[*]  unsupported bit set\n\n");
		return -EINVAL; }
	EC_VMWRITE(pri_cpu_x_ctls.val, PRIMARY_CPU_BASED_X_CTLS, lhf, error_code);
	
	READ_MSR(msr, IA32_VMX_PROCBASED_CTLS2);
	sec_cpu_x_ctls.val|=msr.vmx_ctls.allowed_zeroes;	//uneccessary
	printk("[**] secondary cpu based controls:\t0x%08x\n", sec_cpu_x_ctls.val);
	if( (sec_cpu_x_ctls.val & msr.vmx_ctls.allowed_ones)!=sec_cpu_x_ctls.val ) {
		printk("[*]  unsupported bit set\n\n");
		return -EINVAL; }
	EC_VMWRITE(sec_cpu_x_ctls.val, SECONDARY_CPU_BASED_X_CTLS, lhf, error_code);
	
	READ_MSR(msr, true_flag ? IA32_VMX_TRUE_EXIT_CTLS:IA32_VMX_EXIT_CTLS);
	exit_ctls.val|=msr.vmx_ctls.allowed_zeroes;
	printk("[**] vm exit controls:\t\t\t0x%08x\n", exit_ctls.val);
	if( (exit_ctls.val & msr.vmx_ctls.allowed_ones)!=exit_ctls.val ) {
		printk("[*]  unsupported bit set\n\n");
		return -EINVAL; }
	EC_VMWRITE(exit_ctls.val, EXIT_CTLS, lhf, error_code);
	
	READ_MSR(msr, true_flag ? IA32_VMX_TRUE_ENTRY_CTLS:IA32_VMX_ENTRY_CTLS);
	entry_ctls.val|=msr.vmx_ctls.allowed_zeroes;
	printk("[**] vm entry controls:\t\t\t0x%08x\n", entry_ctls.val);
	if( (entry_ctls.val & msr.vmx_ctls.allowed_ones)!=entry_ctls.val ) {
		printk("[*]  unsupported bit set\n\n");
		return -EINVAL; }
	EC_VMWRITE(entry_ctls.val, ENTRY_CTLS, lhf, error_code);

	
	printk("[*]  initialization complete\n\n");
	
	//////////////////////////
	
	printk("[*]  initializing vmcs registers\n");
	unsigned long reg;
	
	__asm__ __volatile__("mov %%cr0, %0":"=r"(reg)::"memory");
	printk("[**] cr0:\t0x%lx\n", reg);
	READ_MSR(msr, IA32_VMX_CR0_FIXED0);
	if( (reg | msr.val)!=reg ) {
		printk("[*]  unsupported bit clear\n");
		return -EINVAL; }
	READ_MSR(msr, IA32_VMX_CR0_FIXED1);
	if( (reg & msr.val)!=reg ) {
		printk("[*]  unsupported bit set\n");
		return -EINVAL; }
	EC_VMWRITE(reg, GUEST_CR0, lhf, error_code);
	EC_VMWRITE(reg, HOST_CR0, lhf, error_code);
	
	__asm__ __volatile__("mov %%cr3, %0":"=r"(reg)::"memory");
	printk("[**] cr3:\t0x%lx\n", reg);
	EC_VMWRITE(reg, GUEST_CR3, lhf, error_code);
	EC_VMWRITE(reg, HOST_CR3, lhf, error_code);
	
	__asm__ __volatile__("mov %%cr4, %0":"=r"(reg)::"memory");
	printk("[**] cr4:\t0x%lx\n", reg);
	READ_MSR(msr, IA32_VMX_CR4_FIXED0);
	if( (reg | msr.val)!=reg ) {
		printk("[*]  unsupported bit clear\n");
		return -EINVAL; }
	READ_MSR(msr, IA32_VMX_CR4_FIXED1);
	if( (reg & msr.val)!=reg ) {
		printk("[*]  unsupported bit set\n");
		return -EINVAL; }
	EC_VMWRITE(reg, GUEST_CR4, lhf, error_code);
	EC_VMWRITE(reg, HOST_CR4, lhf, error_code);
	
	__asm__ __volatile__("mov %%dr7, %0":"=r"(reg)::"memory");
	printk("[**] dr7:\t0x%lx\n", reg);
	EC_VMWRITE(reg, GUEST_DR7, lhf, error_code);
	
	printk("[**] guest rip:\t0x%lx\n", guest_rip);
	EC_VMWRITE(guest_rip, GUEST_RIP, lhf, error_code);
	printk("[**] host rip:\t0x%lx\n", host_rip);
	EC_VMWRITE(host_rip, HOST_RIP, lhf, error_code);
	printk("[**] guest rsp:\t0x%lx\n", guest_rsp);
	EC_VMWRITE(guest_rsp, GUEST_RSP, lhf, error_code);
	printk("[**] host rsp:\t0x%lx\n", host_rsp);
	EC_VMWRITE(host_rsp, HOST_RSP, lhf, error_code);
	
	
	__asm__ __volatile__("pushf; pop %0":"=r"(reg)::"memory");
	printk("[**] rflags:\t0x%lx\n", reg);
	EC_VMWRITE(reg, GUEST_RFLAGS, lhf, error_code);
	
	
	dtr_t dtr;
	
	__asm__ __volatile__("sidt %0"::"m"(dtr):"memory");
	printk("[**] idtr:\t0x%016lx\n", dtr.base);
	printk("[**]\tlim:\t0x%x\n", dtr.lim_val);
	EC_VMWRITE(dtr.lim_val, GUEST_IDTR_LIMIT, lhf, error_code);
	EC_VMWRITE(dtr.base, GUEST_IDTR_BASE, lhf, error_code);
	EC_VMWRITE(dtr.base, HOST_IDTR_BASE, lhf, error_code);
	
	__asm__ __volatile__("sgdt %0"::"m"(dtr):"memory");
	printk("[**] gdtr:\t0x%016lx\n", dtr.base);
	printk("[**]\tlim:\t0x%x\n", dtr.lim_val);
	EC_VMWRITE(dtr.lim_val, GUEST_GDTR_LIMIT, lhf, error_code);
	EC_VMWRITE(dtr.base, GUEST_GDTR_BASE, lhf, error_code);
	EC_VMWRITE(dtr.base, HOST_GDTR_BASE, lhf, error_code);
	
	unsigned long base;
	unsigned int lim;
	access_rights_t access_rights;
	
	unsigned short tr=0;
	__asm__ __volatile__("str %0"::"m"(tr):"memory");
	printk("[**] tr:\t0x%04x\n", tr);
	EC_VMWRITE(tr, GUEST_TR_SELECTOR, lhf, error_code);
	EC_VMWRITE(tr, HOST_TR_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, tr, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_TR_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, tr, dtr.base);
	EC_VMWRITE(lim, GUEST_TR_LIMIT, lhf, error_code);
	base=0
		| ((long)(((tssd_t *)(dtr.base+tr))->base_addr_0_15))
		| ((long)(((tssd_t *)(dtr.base+tr))->base_addr_16_23)<<16)
		| ((long)(((tssd_t *)(dtr.base+tr))->base_addr_24_31)<<24)
		| ((long)(((tssd_t *)(dtr.base+tr))->base_addr_32_63)<<32);
	printk("[**]\tbase:\t0x%lx\n", base);
	EC_VMWRITE(base, GUEST_TR_BASE, lhf, error_code);
	EC_VMWRITE(base, HOST_TR_BASE, lhf, error_code);

	
	__asm__ __volatile__("sldt %0"::"m"(tr):"memory");
	printk("[**] ldtr:\t0x%04x\n", tr);
	EC_VMWRITE(tr, GUEST_LDTR_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, tr, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_LDTR_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, tr, dtr.base);
	EC_VMWRITE(lim, GUEST_LDTR_LIMIT, lhf, error_code);
	GET_BASE(base, tr, dtr.base);
	EC_VMWRITE(base, GUEST_LDTR_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%cs, %0":"=r"(reg)::"memory");
	printk("[**] cs:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_CS_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_CS_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_CS_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_CS_LIMIT, lhf, error_code);
	GET_BASE(base, reg, dtr.base);
	EC_VMWRITE(base, GUEST_CS_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%ss, %0":"=r"(reg)::"memory");
	printk("[**] ss:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_SS_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_SS_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_SS_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_SS_LIMIT, lhf, error_code);
	GET_BASE(base, reg, dtr.base);
	EC_VMWRITE(base, GUEST_SS_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%ds, %0":"=r"(reg)::"memory");
	printk("[**] ds:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_DS_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_DS_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_DS_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_DS_LIMIT, lhf, error_code);
	GET_BASE(base, reg, dtr.base);
	EC_VMWRITE(base, GUEST_DS_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%es, %0":"=r"(reg)::"memory");
	printk("[**] es:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_ES_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_ES_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_ES_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_ES_LIMIT, lhf, error_code);
	GET_BASE(base, reg, dtr.base);
	EC_VMWRITE(base, GUEST_ES_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%fs, %0":"=r"(reg)::"memory");
	printk("[**] fs:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_FS_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_FS_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_FS_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_FS_LIMIT, lhf, error_code);
	READ_MSR(msr, IA32_FS_BASE);
	base=msr.val;
	printk("[**]\tbase:\t0x%lx\n", base);
	EC_VMWRITE(base, GUEST_FS_BASE, lhf, error_code);
	EC_VMWRITE(base, HOST_FS_BASE, lhf, error_code);
	
	__asm__ __volatile__("mov %%gs, %0":"=r"(reg)::"memory");
	printk("[**] gs:\t0x%02lx\n", reg);
	EC_VMWRITE(reg, GUEST_GS_SELECTOR, lhf, error_code);
	EC_VMWRITE(reg, HOST_GS_SELECTOR, lhf, error_code);
	GET_ACCESS_RIGHTS(access_rights, reg, dtr.base);
	EC_VMWRITE(access_rights.val, GUEST_GS_ACCESS_RIGHTS, lhf, error_code);
	GET_LIM_VAL(lim, reg, dtr.base);
	EC_VMWRITE(lim, GUEST_GS_LIMIT, lhf, error_code);
	READ_MSR(msr, IA32_GS_BASE);
	base=msr.val;
	printk("[**]\tbase:\t0x%lx\n", base);
	EC_VMWRITE(base, GUEST_GS_BASE, lhf, error_code);
	EC_VMWRITE(base, HOST_GS_BASE, lhf, error_code);
	
	printk("[**] vmcs link:\t0x%lx", 0xffffffffffffffff);
	EC_VMWRITE(0xffffffffffffffff, VMCS_LINK_PTR_F, lhf, error_code);

	printk("[**] msrs:\n");
	READ_MSR(msr, IA32_DEBUGCTL);
	printk("[**]\tdbgctl:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_DEBUGCTL_F, lhf, error_code);
	READ_MSR(msr, IA32_SYSENTER_CS);
	READ_MSR(msr, IA32_PAT);
	printk("[**]\tpat:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_PAT_F, lhf, error_code);
	EC_VMWRITE(msr.val, HOST_IA32_PAT_F, lhf, error_code);
	READ_MSR(msr, IA32_EFER);
	printk("[**]\tefer:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_EFER_F, lhf, error_code);
	EC_VMWRITE(msr.val, HOST_IA32_EFER_F, lhf, error_code);
	printk("[**] sysenter msrs:\n");
	printk("[**]\tcs:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_SYSENTER_CS, lhf, error_code);
	EC_VMWRITE(msr.val, HOST_IA32_SYSENTER_CS, lhf, error_code);
	READ_MSR(msr, IA32_SYSENTER_ESP);
	printk("[**]\tesp:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_SYSENTER_ESP, lhf, error_code);
	EC_VMWRITE(msr.val, HOST_IA32_SYSENTER_ESP, lhf, error_code);
	READ_MSR(msr, IA32_SYSENTER_EIP);
	printk("[**]\teip:\t0x%lx\n", msr.val);
	EC_VMWRITE(msr.val, GUEST_IA32_SYSENTER_EIP, lhf, error_code);
	EC_VMWRITE(msr.val, HOST_IA32_SYSENTER_EIP, lhf, error_code);
	
	printk("[*]  initialization complete\n\n");
	return 0; }

#endif
